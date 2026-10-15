use crate::{
    Credentials, Error, Result,
    crypto::{CommandCipher, MARKER, challenge_hash},
};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read as _, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use zeroize::Zeroizing;

const LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoints {
    pub command_host: String,
}

fn trusted_host(host: &str) -> bool {
    host.ends_with(".idrive.com")
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

pub async fn discover(credentials: &Credentials) -> Result<Endpoints> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut response = client
        .post("https://evs.idrive.com/cgi-bin/get_idevs_server_ip.pl")
        .form(&[
            ("username", credentials.username.as_str()),
            ("password", credentials.password.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?;
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        return Err(Error::Frame("discovery response too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > LIMIT {
            return Err(Error::Frame("discovery response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    let attributes = xml_attributes(&body)?;
    let get = |key: &str| attributes.iter().find_map(|v| v.get(key).cloned());
    if get("message").as_deref() != Some("SUCCESS") {
        return Err(Error::Rejected);
    }
    let command_host = get("cmdUtilServerDNS").ok_or(Error::Frame("missing command endpoint"))?;
    if !trusted_host(&command_host) {
        return Err(Error::Frame("untrusted discovery endpoint"));
    }
    Ok(Endpoints { command_host })
}

pub fn xml_attributes(data: &[u8]) -> Result<Vec<BTreeMap<String, String>>> {
    let mut reader = Reader::from_reader(data);
    let mut entries = Vec::new();
    loop {
        match reader
            .read_event()
            .map_err(|_| Error::Frame("invalid XML"))?
        {
            Event::Start(e) | Event::Empty(e) => {
                let mut attributes = BTreeMap::new();
                for attribute in e.attributes() {
                    let a = attribute.map_err(|_| Error::Frame("invalid XML attribute"))?;
                    let key = std::str::from_utf8(a.key.as_ref())
                        .map_err(|_| Error::Frame("invalid attribute name"))?
                        .to_owned();
                    let value = a
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(|_| Error::Frame("invalid attribute value"))?
                        .into_owned();
                    attributes.insert(key, value);
                }
                if !attributes.is_empty() {
                    entries.push(attributes);
                }
            }
            Event::Eof => return Ok(entries),
            Event::DocType(_) => return Err(Error::Frame("DTD is not supported")),
            _ => {}
        }
    }
}

#[derive(Clone, Copy)]
enum DataEncryption {
    Unknown,
    Default,
    Private,
}

pub struct Session {
    stream: BufReader<TcpStream>,
    cipher: CommandCipher,
    pub canonical_username: Zeroizing<String>,
    multiplex: bool,
    remaining: usize,
    encryption: DataEncryption,
}

impl Session {
    pub async fn connect(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        operation: i32,
    ) -> Result<Self> {
        timeout(
            Duration::from_secs(30),
            Self::handshake(endpoints, credentials, operation),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    async fn handshake(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        operation: i32,
    ) -> Result<Self> {
        if credentials.username.is_empty()
            || credentials.username.len() > 255
            || credentials
                .username
                .chars()
                .any(|c| c.is_whitespace() || c == '\0')
            || credentials.password.is_empty()
            || credentials.password.len() > 255
        {
            return Err(Error::Frame("invalid username or password length"));
        }
        if !trusted_host(&endpoints.command_host) {
            return Err(Error::Frame("untrusted command endpoint"));
        }
        let socket = TcpStream::connect((endpoints.command_host.as_str(), 443)).await?;
        socket.set_nodelay(true)?;
        let mut session = Self {
            stream: BufReader::with_capacity(128 * 1024, socket),
            cipher: CommandCipher::greeting(),
            canonical_username: Zeroizing::new(credentials.username.to_string()),
            multiplex: false,
            remaining: 0,
            encryption: DataEncryption::Unknown,
        };
        let greeting = format!("@IDEVSD: 29[{}:IDRIVE_RS:-1", credentials.username.as_str());
        let greeting = format!("{MARKER}{}", session.cipher.encode(&greeting)?);
        session.write_line(&greeting).await?;
        let response = session.read_line().await?;
        if !response.starts_with("@IDEVSD: ") {
            return Err(Error::Frame("invalid server greeting"));
        }
        let module = format!("{MARKER}{}", session.cipher.encode("ibackup")?);
        session.write_line(&module).await?;
        let greeting_cipher = CommandCipher::greeting();
        for _ in 0..32 {
            let line = session.read_line().await?;
            let line = if let Some(encoded) = line.strip_prefix(MARKER) {
                greeting_cipher.decode(encoded)?
            } else {
                line
            };
            if let Some(challenge) = line.strip_prefix("@IDEVSD: AUTHREQD ") {
                if std::env::var_os("IDRIVE_TRACE").is_some() {
                    eprintln!("protocol: authentication challenge received");
                }
                session.cipher = CommandCipher::derive(challenge.as_bytes(), challenge.as_bytes());
                let attempts = if credentials.username.contains('@') {
                    2
                } else {
                    1
                };
                for attempt in 0..attempts {
                    let user = session.canonical_username.as_str();
                    let hash =
                        challenge_hash(credentials.password.as_bytes(), challenge.as_bytes());
                    let private = credentials
                        .private_key
                        .as_ref()
                        .map(|key| challenge_hash(user.as_bytes(), key.as_bytes()));
                    let default = challenge_hash(user.as_bytes(), user.as_bytes());
                    let login = Zeroizing::new(format!(
                        "{} {} {} 4e6b7b2b-0218-4f7f-9c45-578aa67ecf72 stream {}",
                        user,
                        hash.as_str(),
                        private.as_ref().map(|p| p.as_str()).unwrap_or(""),
                        default.as_str()
                    ));
                    let encrypted = Zeroizing::new(session.cipher.encrypt_bytes(login.as_bytes()));
                    session.write_i32(operation).await?;
                    session.write_i32(encrypted.len() as i32).await?;
                    session.write_packet(&encrypted).await?;
                    if attempt == 0 {
                        session
                            .write_i32(i32::from(credentials.username.contains('@')))
                            .await?;
                        if attempts == 2 {
                            let bytes = session.read_blob().await?;
                            if bytes.is_empty() {
                                break;
                            }
                            session.canonical_username = Zeroizing::new(
                                String::from_utf8(bytes)
                                    .map_err(|_| Error::Frame("invalid canonical username"))?
                                    .trim_end_matches(char::from(0))
                                    .to_owned(),
                            );
                        }
                    }
                }
            } else if line.starts_with("@IDEVSD KEY TYPE") {
                let kind = line
                    .split_once(':')
                    .map(|(_, v)| v.trim())
                    .ok_or(Error::Frame("invalid encryption type response"))?;
                session.encryption = match kind {
                    "DEFAULT" => DataEncryption::Default,
                    "PRIVATE" => DataEncryption::Private,
                    _ => return Err(Error::Unsupported("unknown account encryption type")),
                };
            } else if line == "@IDEVSD: OK" {
                if std::env::var_os("IDRIVE_TRACE").is_some() {
                    eprintln!("protocol: authentication accepted");
                }
                return Ok(session);
            } else if line.starts_with("@ERROR") || line == "@IDEVSD: EXIT" {
                if std::env::var_os("IDRIVE_TRACE").is_some() {
                    eprintln!("protocol: authentication rejected");
                }
                if line.contains("PROTOCOL VERSION MISMATCH") {
                    return Err(Error::Unsupported(
                        "legacy protocol required; deduplicated accounts are not supported",
                    ));
                }
                return Err(Error::Rejected);
            }
        }
        Err(Error::Frame("too many handshake messages"))
    }

    fn data_cipher(&self, credentials: &Credentials) -> Result<CommandCipher> {
        let secret = match self.encryption {
            DataEncryption::Default => self.canonical_username.as_bytes(),
            DataEncryption::Private => credentials
                .private_key
                .as_ref()
                .ok_or(Error::Unsupported("a private encryption key is required"))?
                .as_bytes(),
            DataEncryption::Unknown => {
                return Err(Error::Unsupported(
                    "server did not identify account encryption",
                ));
            }
        };
        Ok(CommandCipher::derive(secret, secret))
    }

    pub async fn write_line(&mut self, text: &str) -> Result<()> {
        let mut line = text.as_bytes().to_vec();
        line.push(b'\n');
        self.write_packet(&line).await
    }
    pub async fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        let read = timeout(
            Duration::from_secs(60),
            (&mut self.stream).take(16385).read_until(b'\n', &mut line),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        if read == 0 {
            return Err(Error::Closed);
        }
        if read > 16384 || !line.ends_with(b"\n") {
            return Err(Error::Frame("line exceeds limit or lacks delimiter"));
        }
        while line.last().is_some_and(|v| *v == b'\n' || *v == b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| Error::Frame("invalid line encoding"))
    }
    pub async fn write_i32(&mut self, value: i32) -> Result<()> {
        self.write_packet(&value.to_le_bytes()).await
    }
    pub async fn read_data(&mut self, out: &mut [u8]) -> Result<()> {
        timeout(Duration::from_secs(60), self.read_data_inner(out))
            .await
            .map_err(|_| Error::Timeout)?
    }
    async fn read_data_inner(&mut self, out: &mut [u8]) -> Result<()> {
        if !self.multiplex {
            self.stream.read_exact(out).await?;
            return Ok(());
        }
        let mut offset = 0;
        while offset < out.len() {
            if self.remaining == 0 {
                let header = self.stream.read_u32_le().await?;
                let length = (header & 0xffffff) as usize;
                let channel = header >> 24;
                if length > LIMIT {
                    return Err(Error::Frame("multiplex packet too large"));
                }
                if channel == 7 {
                    self.remaining = length;
                } else if channel == 8 || channel == 9 {
                    let mut bytes = vec![0; length];
                    self.stream.read_exact(&mut bytes).await?;
                    if channel == 8 {
                        return Err(Error::Rejected);
                    }
                } else {
                    return Err(Error::Frame("unsupported multiplex channel"));
                }
                continue;
            }
            let take = self.remaining.min(out.len() - offset);
            self.stream
                .read_exact(&mut out[offset..offset + take])
                .await?;
            self.remaining -= take;
            offset += take;
        }
        Ok(())
    }
    pub async fn read_u8(&mut self) -> Result<u8> {
        let mut bytes = [0; 1];
        self.read_data(&mut bytes).await?;
        Ok(bytes[0])
    }
    pub async fn read_i32(&mut self) -> Result<i32> {
        let mut bytes = [0; 4];
        self.read_data(&mut bytes).await?;
        Ok(i32::from_le_bytes(bytes))
    }
    pub async fn read_long(&mut self) -> Result<i64> {
        let first = self.read_i32().await?;
        if first != -1 {
            return Ok(first as i64);
        }
        let mut bytes = [0; 8];
        self.read_data(&mut bytes).await?;
        Ok(i64::from_le_bytes(bytes))
    }
    pub async fn read_blob(&mut self) -> Result<Vec<u8>> {
        let length = self.read_i32().await?;
        if length < 0 || length as usize > LIMIT {
            if length.to_le_bytes() == *b"@ERR" {
                return Err(Error::Rejected);
            }
            return Err(Error::Frame("invalid blob length"));
        }
        let mut bytes = vec![0; length as usize];
        self.read_data(&mut bytes).await?;
        Ok(bytes)
    }

    pub async fn command(&mut self, arguments: &[String]) -> Result<()> {
        for arg in arguments {
            let encoded = self.cipher.encode(arg)?;
            self.write_line(&encoded).await?;
        }
        self.write_line("").await?;
        let status = self.read_i32().await?;
        if status > 0 {
            if status as usize > LIMIT {
                return Err(Error::Frame("error message exceeds limit"));
            }
            let mut response = vec![0; status as usize];
            self.read_data(&mut response).await?;
            return Err(Error::Rejected);
        }
        Ok(())
    }

    pub async fn read_protocol_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        for _ in 0..16384 {
            let byte = self.read_u8().await?;
            if byte == b'\n' {
                return String::from_utf8(line).map_err(|_| Error::Frame("invalid protocol line"));
            }
            if byte != b'\r' {
                line.push(byte);
            }
        }
        Err(Error::Frame("protocol line exceeds limit"))
    }
    pub async fn write_long(&mut self, value: i64) -> Result<()> {
        self.write_packet(&long_bytes(value)).await
    }
    pub async fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        timeout(
            Duration::from_secs(60),
            self.stream.get_mut().write_all(bytes),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(())
    }
    pub async fn mkdir(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        path: &str,
    ) -> Result<()> {
        validate_path(path)?;
        let mut s = Self::connect(endpoints, credentials, 0).await?;
        let mut args = [
            "--server",
            "--sender",
            "--xml-output",
            "-v",
            "--list-only",
            "-B32768",
            "--timeout=700",
        ]
        .map(str::to_owned)
        .to_vec();
        args.push(format!("--create-dir={path}"));
        args.extend(["--inplace", ".", "ibackup/"].map(str::to_owned));
        s.command(&args).await?;
        let line = s.read_line().await?;
        let decoded = s.cipher.decode(&line)?;
        if decoded.starts_with("@ERROR") {
            return Err(Error::Rejected);
        }
        if !xml_attributes(decoded.as_bytes())?
            .iter()
            .any(|a| a.get("op_status").is_some_and(|v| v == "success"))
        {
            return Err(Error::Frame("unrecognized directory result"));
        }
        Ok(())
    }
    pub async fn upload(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        local: &std::path::Path,
        remote: &str,
    ) -> Result<u64> {
        use md4::{Digest, Md4};
        use std::time::{SystemTime, UNIX_EPOCH};
        validate_path(remote)?;
        let (parent, name) = remote
            .rsplit_once('/')
            .ok_or(Error::Frame("missing filename"))?;
        if name.is_empty() {
            return Err(Error::Frame("missing filename"));
        }
        let file = tokio::fs::File::open(local).await?;
        let metadata = file.metadata().await?;
        let mut file = BufReader::with_capacity(1024 * 1024, file);
        if !metadata.is_file() {
            return Err(Error::Frame("source is not a regular file"));
        }
        let size = metadata.len();
        let modified = metadata
            .modified()
            .unwrap_or(SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Frame("unsupported modification time"))?
            .as_secs();
        let mut s = Self::connect(endpoints, credentials.clone(), 9).await?;
        let mut args = [
            "--server",
            "--xml-output",
            "-vtrR",
            "-B32768",
            "--timeout=900",
            "--inplace",
            ".",
        ]
        .map(str::to_owned)
        .to_vec();
        args.push(format!("ibackup{parent}/"));
        s.command(&args).await?;
        let _seed = s.read_long().await?;
        s.multiplex = true;
        let (encrypted_name, compressed) = compress_encrypt(&s.cipher, name.as_bytes())?;
        let mut entry = vec![0x18];
        entry.extend_from_slice(&(encrypted_name.len() as i32).to_le_bytes());
        entry.extend_from_slice(&compressed.to_le_bytes());
        entry.extend_from_slice(&encrypted_name);
        entry.extend_from_slice(&long_bytes(size as i64));
        entry.extend_from_slice(&long_bytes(0));
        entry.extend_from_slice(&(modified as i32).to_le_bytes());
        entry.extend_from_slice(&0o100600i32.to_le_bytes());
        entry.push(0);
        entry.extend_from_slice(&0i32.to_le_bytes());
        entry.extend_from_slice(&(-1i32).to_le_bytes());
        s.write_packet(&entry).await?;
        if s.read_protocol_line().await? != MARKER {
            return Err(Error::Frame("missing calibration acknowledgement"));
        }
        let data_cipher = s.data_cipher(&credentials)?;
        let mut transferred = false;
        let version = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let mut phases = 0;
        loop {
            let index = s.read_i32().await?;
            trace_number("upload request index", index as i64);
            if index == -1 {
                phases += 1;
                s.write_i32(-1).await?;
                if phases == 3 {
                    break;
                }
                continue;
            }
            let mut short = [0; 2];
            s.read_data(&mut short).await?;
            let flags = u16::from_le_bytes(short);
            trace_number("upload request flags", flags as i64);
            if index == 1 && flags == 0x2000 {
                s.write_i32(1).await?;
                s.write_packet(&short).await?;
                continue;
            }
            if index != 0 || flags & 0x1800 != 0 {
                return Err(Error::Unsupported("upload request attributes"));
            }
            if flags & 0x8000 == 0 {
                continue;
            }
            for _ in 0..1000 {
                if s.read_i32().await? == -1 {
                    break;
                }
            }
            let seed = s.read_long().await?;
            let count = s.read_i32().await?;
            let _block_length = s.read_i32().await?;
            let checksum_length = s.read_i32().await?;
            let _remainder = s.read_i32().await?;
            trace_number("upload existing blocks", count as i64);
            if count != 0 || !(0..=16).contains(&checksum_length) {
                return Err(Error::Unsupported(
                    "incremental overwrite is not implemented",
                ));
            }
            if transferred {
                return Err(Error::Frame("server requested a retransmission"));
            }
            s.write_i32(0).await?;
            s.write_packet(&short).await?;
            s.write_long(version).await?;
            let (user, compression) = compress_encrypt(&s.cipher, s.canonical_username.as_bytes())?;
            s.write_i32(user.len() as i32).await?;
            s.write_packet(&user).await?;
            s.write_i32(compression).await?;
            s.write_long(seed).await?;
            let mut digest = Md4::new();
            digest.update((seed as i32).to_le_bytes());
            let mut offset = 0u64;
            let mut encrypted_offset = 0i64;
            let mut buffer = vec![0; 32768];
            let mut compress_data = None;
            loop {
                let n = file.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                let plain = &buffer[..n];
                let candidate = if compress_data != Some(false) {
                    Some(compress_encrypt_fast(&data_cipher, plain)?)
                } else {
                    None
                };
                if compress_data.is_none() {
                    compress_data = Some(
                        candidate
                            .as_ref()
                            .is_some_and(|(bytes, _)| bytes.len() * 16 < n * 15),
                    );
                }
                let (encrypted, compression) = if compress_data == Some(true) {
                    candidate.ok_or(Error::Frame("missing compressed block"))?
                } else {
                    let encrypted = data_cipher.encrypt_bytes(plain);
                    let padding = n as i32 - encrypted.len() as i32;
                    (encrypted, padding)
                };
                digest.update(&encrypted);
                let mut packet = Vec::with_capacity(encrypted.len() + 128);
                packet.extend_from_slice(&(encrypted.len() as i32).to_le_bytes());
                packet.extend_from_slice(&encrypted);
                if size > 32768 {
                    packet.extend_from_slice(&long_bytes(offset as i64));
                    packet.extend_from_slice(&long_bytes(offset as i64));
                    packet.extend_from_slice(&long_bytes(encrypted_offset));
                    for value in [
                        n as i32,
                        compression,
                        encrypted.len() as i32,
                        weak_checksum(plain) as i32,
                    ] {
                        packet.extend_from_slice(&value.to_le_bytes());
                    }
                    packet.extend_from_slice(&long_bytes(version));
                    packet.extend_from_slice(&block_checksum(plain, seed));
                    packet.extend_from_slice(&block_checksum(&encrypted, seed));
                } else {
                    packet.extend_from_slice(&compression.to_le_bytes());
                }
                s.write_packet(&packet).await?;
                encrypted_offset += encrypted.len() as i64;
                offset += n as u64;
            }
            if offset != size {
                return Err(Error::Frame("source file changed during upload"));
            }
            s.write_i32(0).await?;
            s.write_packet(&digest.finalize()).await?;
            transferred = true;
        }
        if !transferred {
            return Err(Error::Frame("server did not request file content"));
        }
        // Consume the generator's final completion marker.
        for _ in 0..32 {
            let index = s.read_i32().await?;
            if index == -1 {
                return Ok(size);
            }
            let mut flags = [0; 2];
            s.read_data(&mut flags).await?;
            if index != 1 || u16::from_le_bytes(flags) != 0x2000 {
                return Err(Error::Frame("unexpected upload completion"));
            }
            s.write_i32(index).await?;
            s.write_packet(&flags).await?;
        }
        Err(Error::Frame("upload did not complete"))
    }
    pub async fn download(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        remote: &str,
        local: &std::path::Path,
    ) -> Result<u64> {
        if tokio::fs::try_exists(local).await? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination already exists",
            )
            .into());
        }
        let parent = local
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        let file = tokio::fs::File::from_std(temporary.reopen()?);
        let mut output = tokio::io::BufWriter::with_capacity(1024 * 1024, file);
        let bytes = Self::download_to(endpoints, credentials, remote, &mut output).await?;
        output.get_ref().sync_all().await?;
        drop(output);
        temporary
            .persist_noclobber(local)
            .map_err(|e| Error::Io(e.error))?;
        Ok(bytes)
    }

    pub async fn download_to<W: tokio::io::AsyncWrite + Unpin>(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        remote: &str,
        output: &mut W,
    ) -> Result<u64> {
        use md4::{Digest, Md4};
        validate_path(remote)?;
        let mut s = Self::connect(endpoints, credentials.clone(), 0).await?;
        let args = [
            "--server",
            "--sender",
            "--xml-output",
            "--add-progress",
            "-vtrR",
            "-B32768",
            "--timeout=900",
            "--inplace",
            "--files-from=-",
            "--from0",
            ".",
            "ibackup/",
        ];
        s.command(&args.map(str::to_owned)).await?;
        let _seed = s.read_long().await?;
        s.multiplex = true;
        s.write_i32(0).await?;
        let mut names = remote.trim_start_matches('/').as_bytes().to_vec();
        names.push(0);
        let (names, compressed) = compress_encrypt(&s.cipher, &names)?;
        s.write_i32(names.len() as i32).await?;
        s.write_i32(compressed).await?;
        s.write_packet(&names).await?;
        let (end, compression) = compress_encrypt(&s.cipher, &[0])?;
        s.write_i32(end.len() as i32).await?;
        s.write_i32(compression).await?;
        s.write_packet(&end).await?;
        let entries = s.read_entries(false).await?;
        trace_number("restore entries", entries.len() as i64);
        let mut indices: Vec<_> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_directory)
            .collect();
        if indices.len() != 1 {
            return Err(Error::Frame("expected exactly one regular file"));
        }
        let (index, entry) = indices.pop().unwrap();
        trace_number("restore size", entry.size as i64);
        s.write_i32(index as i32).await?;
        s.write_packet(&0xa000u16.to_le_bytes()).await?;
        s.write_i32(0).await?;
        for _ in 0..3 {
            s.write_i32(-1).await?;
        }
        let received_index = s.read_i32().await?;
        trace_number("restore response index", received_index as i64);
        if received_index != index as i32 {
            return Err(Error::Frame("unexpected restore index"));
        }
        let mut flags = [0; 2];
        s.read_data(&mut flags).await?;
        let flags = u16::from_le_bytes(flags);
        trace_number("restore response flags", flags as i64);
        if flags & 0x8000 == 0 || flags & 0x1800 != 0 {
            return Err(Error::Unsupported("restore response attributes"));
        }
        let seed = s.read_long().await?;
        let count = s.read_i32().await?;
        let _block_length = s.read_i32().await?;
        let checksum_length = s.read_i32().await?;
        let _remainder = s.read_i32().await?;
        trace_number("restore block count", count as i64);
        if !(0..=1_000_000).contains(&count) || !(0..=16).contains(&checksum_length) {
            return Err(Error::Frame("invalid restore block table"));
        }
        let mut compressions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            compressions.push(s.read_i32().await?);
        }
        let data_cipher = s.data_cipher(&credentials)?;
        let mut digest = Md4::new();
        digest.update((seed as i32).to_le_bytes());
        let mut total = 0u64;
        let mut block = 0;
        loop {
            let length = s.read_i32().await?;
            if length == 0 {
                break;
            }
            if !(1..=65536).contains(&length) {
                return Err(Error::Frame("invalid restore token"));
            }
            let mut encrypted = vec![0; length as usize];
            s.read_data(&mut encrypted).await?;
            if encrypted == b"504b413d-afad-4725" {
                continue;
            }
            let compression = *compressions
                .get(block)
                .ok_or(Error::Frame("missing block metadata"))?;
            digest.update(&encrypted);
            let decoded = decrypt_block(&data_cipher, &encrypted, compression, 65536)?;
            total += decoded.len() as u64;
            if total > entry.size {
                return Err(Error::Frame("restore exceeds expected length"));
            }
            output.write_all(&decoded).await?;
            block += 1;
        }
        let mut expected = [0; 16];
        s.read_data(&mut expected).await?;
        let actual: [u8; 16] = digest.finalize().into();
        if actual != expected || total != entry.size || block != compressions.len() {
            return Err(Error::Frame("restore checksum or length mismatch"));
        }
        for _ in 0..3 {
            if s.read_i32().await? != -1 {
                return Err(Error::Frame("unexpected restore phase"));
            }
        }
        s.write_i32(-1).await?;
        output.flush().await?;
        Ok(total)
    }
    pub async fn list(
        endpoints: &Endpoints,
        credentials: Arc<Credentials>,
        path: &str,
    ) -> Result<Vec<RemoteEntry>> {
        if !path.starts_with('/')
            || path.contains(['\0', '\n', '\r'])
            || path.split('/').any(|p| p == "..")
        {
            return Err(Error::Frame("invalid remote path"));
        }
        let mut s = Self::connect(endpoints, credentials, 21).await?;
        let args = [
            "--server",
            "--sender",
            "--auth-list2",
            "--xml-output",
            "-vnr",
            "--list-only",
            "-B32768",
            "--timeout=700",
            "--inplace",
            ".",
        ];
        let mut args = args.map(str::to_owned).to_vec();
        args.push(format!("ibackup{path}"));
        s.command(&args).await?;
        let _checksum_seed = s.read_long().await?;
        s.multiplex = true;
        s.write_i32(0).await?;
        s.read_entries(true).await
    }
    async fn read_entries(&mut self, listing: bool) -> Result<Vec<RemoteEntry>> {
        let mut entries = Vec::new();
        let mut previous = Vec::new();
        let mut modified = 0;
        let mut mode = 0;
        loop {
            let mut flags = self.read_u8().await? as u16;
            if flags == 0 {
                break;
            }
            if flags & 4 != 0 {
                flags |= (self.read_u8().await? as u16) << 8;
            }
            let prefix = if flags & 0x20 != 0 {
                self.read_u8().await? as usize
            } else {
                0
            };
            if prefix > previous.len() {
                return Err(Error::Frame("invalid filename prefix"));
            }
            let encrypted_len = self.read_i32().await?;
            let compression = self.read_i32().await?;
            if !(0..=8192).contains(&encrypted_len) {
                return Err(Error::Frame("invalid filename length"));
            }
            let mut encrypted = vec![0; encrypted_len as usize];
            self.read_data(&mut encrypted).await?;
            let suffix = decrypt_block(&self.cipher, &encrypted, compression, 4096)?;
            previous.truncate(prefix);
            previous.extend_from_slice(&suffix);
            if previous.len() > 4096 {
                return Err(Error::Frame("filename too large"));
            }
            let size = self.read_long().await?;
            let versions = if listing { self.read_i32().await? } else { 0 };
            if listing {
                let _thumbnail = self.read_i32().await?;
            }
            let directory = if listing { self.read_i32().await? } else { 0 };
            if flags & 0x80 == 0 {
                modified = self.read_i32().await?;
            }
            if flags & 2 == 0 {
                mode = self.read_i32().await?;
            }
            if flags & 0x200 != 0 {
                return Err(Error::Unsupported("hardlinked listing entry"));
            }
            entries.push(RemoteEntry {
                path: wire_path(&previous)?,
                size: u64::try_from(size).map_err(|_| Error::Frame("negative file size"))?,
                is_directory: directory != 0 || mode & 0xf000 == 0x4000,
                modified: modified as i64,
                versions,
            });
            if entries.len() > 100000 {
                return Err(Error::Frame("directory entry limit exceeded"));
            }
        }
        let io_error = self.read_i32().await?;
        if io_error != 0 {
            return Err(Error::Frame("server reported listing error"));
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub path: String,
    pub size: u64,
    pub is_directory: bool,
    pub modified: i64,
    pub versions: i32,
}

fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.contains(['\0', '\n', '\r'])
        || path.split('/').any(|v| v == "..")
    {
        return Err(Error::Frame("invalid remote path"));
    }
    Ok(())
}
fn trace_number(label: &str, value: i64) {
    if std::env::var_os("IDRIVE_TRACE").is_some() {
        eprintln!("protocol: {label}={value}");
    }
}
fn long_bytes(value: i64) -> Vec<u8> {
    if (0..=i32::MAX as i64).contains(&value) {
        (value as i32).to_le_bytes().to_vec()
    } else {
        let mut bytes = (-1i32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}
fn compress_encrypt(cipher: &CommandCipher, bytes: &[u8]) -> Result<(Vec<u8>, i32)> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    Ok((cipher.encrypt_bytes(&compressed), compressed.len() as i32))
}
fn compress_encrypt_fast(cipher: &CommandCipher, bytes: &[u8]) -> Result<(Vec<u8>, i32)> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    Ok((cipher.encrypt_bytes(&compressed), compressed.len() as i32))
}
fn block_checksum(bytes: &[u8], seed: i64) -> [u8; 16] {
    use md4::{Digest, Md4};
    let mut md = Md4::new();
    md.update(bytes);
    if seed != 0 {
        md.update((seed as i32).to_le_bytes());
    }
    md.finalize().into()
}
fn weak_checksum(bytes: &[u8]) -> u32 {
    let mut first = 0u32;
    let mut second = 0u32;
    for byte in bytes {
        first = first.wrapping_add(*byte as i8 as i32 as u32);
        second = second.wrapping_add(first);
    }
    (second << 16).wrapping_add(first & 65535)
}

fn wire_path(bytes: &[u8]) -> Result<String> {
    let path = std::str::from_utf8(bytes).map_err(|_| Error::Frame("filename is not UTF-8"))?;
    Ok(path
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(path)
        .to_owned())
}
fn decrypt_block(
    cipher: &CommandCipher,
    encrypted: &[u8],
    compression: i32,
    max: u64,
) -> Result<Vec<u8>> {
    let plain = cipher.decrypt_bytes(encrypted)?;
    if compression > 0 {
        if compression as usize > plain.len() {
            return Err(Error::Frame("invalid compression length"));
        }
        let mut decoded = Vec::new();
        std::io::Read::take(
            flate2::read::ZlibDecoder::new(&plain[..compression as usize]),
            max + 1,
        )
        .read_to_end(&mut decoded)?;
        if decoded.len() as u64 > max {
            return Err(Error::Frame("decompressed block exceeds limit"));
        }
        Ok(decoded)
    } else {
        let length = plain.len() as i64 + compression as i64;
        if length < 0 || length as u64 > max {
            return Err(Error::Frame("invalid block padding"));
        }
        Ok(plain[..length as usize].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_hosts_cannot_redirect_credentials_elsewhere() {
        assert!(trusted_host("evs123.idrive.com"));
        for host in [
            "idrive.com.attacker.test",
            "evs.idrive.com:443",
            "evs.idrive.com/path",
            "evil@evs.idrive.com",
            "\nevs.idrive.com",
            ".idrive.com",
            "x..idrive.com",
            "-x.idrive.com",
        ] {
            assert!(!trusted_host(host), "{host:?}");
        }
    }
    #[test]
    fn traversal_and_line_injection_are_rejected() {
        for path in ["relative", "/../x", "/a/../x", "/x\n--server", "/x\0y"] {
            assert!(validate_path(path).is_err());
        }
        assert!(validate_path("/photos/année 2026.jpg").is_ok());
    }
    #[test]
    fn vendor_restore_selection_terminator_is_separate_encrypted_packet() {
        // Captured from the vendor with synthetic challenge and a one-byte NUL terminator.
        let cipher = CommandCipher::derive(b"synthetic-challenge", b"synthetic-challenge");
        let bytes = [
            0x26, 0x1b, 0x2d, 0x16, 0xb1, 0x3b, 0x93, 0x0a, 0x0b, 0x4c, 0x38, 0x3d, 0x98, 0x92,
            0x71, 0x60,
        ];
        assert_eq!(decrypt_block(&cipher, &bytes, 9, 4096).unwrap(), [0]);
    }
    #[test]
    fn compressed_blocks_cannot_expand_past_limit() {
        let c = CommandCipher::greeting();
        let (enc, n) = compress_encrypt(&c, &vec![0; 65536]).unwrap();
        assert!(decrypt_block(&c, &enc, n, 4096).is_err());
        assert!(decrypt_block(&c, &[0; 15], 0, 4096).is_err());
        assert!(decrypt_block(&c, &[0; 16], -17, 4096).is_err());
        assert!(decrypt_block(&c, &[0; 16], 17, 4096).is_err());
    }
    #[test]
    fn zero_salt_seeded_checksum_matches_rsync_md4_layout() {
        // Independent RFC 1320 MD4 empty-input vector and sign-sensitive weak checksum.
        assert_eq!(
            block_checksum(b"", 0),
            [
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
                0x89, 0xc0
            ]
        );
        assert_eq!(weak_checksum(&[0xff]), 0xffffffff);
        assert_eq!(long_bytes(-1), [0xff; 12]);
    }
    #[test]
    fn xml_dtd_is_rejected_and_entities_are_unescaped() {
        assert!(xml_attributes(b"<!DOCTYPE root><root/>").is_err());
        assert_eq!(
            xml_attributes(b"<tree><item path=\"a&amp;b\"/></tree>").unwrap()[0]["path"],
            "a&b"
        );
    }
}
