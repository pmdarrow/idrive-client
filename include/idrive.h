#ifndef IDRIVE_CORE_H
#define IDRIVE_CORE_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct IdriveHandle IdriveHandle;
/* Blocking calls: use a background queue. JSON: username, password, private_key?. */
IdriveHandle *idrive_client_open(const char *credentials_json);
/* JSON operations: list(path), mkdir(path), upload(local,remote), download(remote,local).
 * Response: {"ok":true,"result":...} or {"ok":false,"error":"..."}.
 * Inputs are borrowed until return. Free each response once. */
char *idrive_client_call(IdriveHandle *client, const char *request_json);
void idrive_string_free(char *text);
/* Close only after all calls finish. */
void idrive_client_close(IdriveHandle *client);
#ifdef __cplusplus
}
#endif
#endif
