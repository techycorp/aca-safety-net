//! Azure CLI analysis - blocks commands that expose secrets.
//!
//! `az account get-access-token` is allowed: it prints a short-lived OAuth2
//! access token (about an hour), not the refresh token or service-principal
//! secret behind it. Long-lived secrets stay blocked: Key Vault secrets,
//! account keys, connection strings, SAS tokens, publishing credentials and
//! new service-principal credentials.

use super::argv::{CliRule, Hit};
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

fn hit(rule: &'static str, reason: &str) -> Option<Hit> {
    Some((rule, reason.to_string()))
}

fn classify(words: &[&str]) -> Option<Hit> {
    if words.len() < 3 {
        return None;
    }

    // Azure CLI structure: az <group> [subgroup...] <command> [options]
    let group = words[1];

    match group {
        // az acr credential show
        "acr" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "credential" && words[3] == "show" {
                hit(
                    "az.acr.credentials",
                    "az acr credential show exposes container registry credentials",
                )
            } else {
                None
            }
        }

        // az ad sp/app credential operations
        "ad" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "sp" => match words[3] {
                    "create-for-rbac" => hit(
                        "az.ad.sp.create",
                        "az ad sp create-for-rbac exposes new service principal credentials",
                    ),
                    "credential" => {
                        if words.len() >= 5 && words[4] == "reset" {
                            hit(
                                "az.ad.sp.credential-reset",
                                "az ad sp credential reset exposes new service principal password",
                            )
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
                "app" => {
                    if words[3] == "credential" && words.len() >= 5 && words[4] == "reset" {
                        hit(
                            "az.ad.app.credential-reset",
                            "az ad app credential reset exposes new app client secret",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az aks get-credentials
        "aks" => match words[2] {
            "get-credentials" => hit(
                "az.aks.credentials",
                "az aks get-credentials exposes Kubernetes cluster credentials",
            ),
            _ => None,
        },

        // az appconfig credential list
        "appconfig" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "credential" && words[3] == "list" {
                hit(
                    "az.appconfig.credentials",
                    "az appconfig credential list exposes App Configuration access keys",
                )
            } else {
                None
            }
        }

        // az batch account keys list
        "batch" => {
            if words.len() < 5 {
                return None;
            }
            if words[2] == "account" && words[3] == "keys" && words[4] == "list" {
                hit(
                    "az.batch.keys",
                    "az batch account keys list exposes Batch account access keys",
                )
            } else {
                None
            }
        }

        // az cognitiveservices account keys list
        "cognitiveservices" => {
            if words.len() < 5 {
                return None;
            }
            if words[2] == "account" && words[3] == "keys" && words[4] == "list" {
                hit(
                    "az.cognitiveservices.keys",
                    "az cognitiveservices account keys list exposes API keys",
                )
            } else {
                None
            }
        }

        // az communication list-key
        "communication" => match words[2] {
            "list-key" => hit(
                "az.communication.keys",
                "az communication list-key exposes Communication Services access keys",
            ),
            _ => None,
        },

        // az containerapp secret/job operations
        "containerapp" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "secret" => match words[3] {
                    "show" => hit(
                        "az.containerapp.secret",
                        "az containerapp secret show exposes secret value",
                    ),
                    "list" => {
                        if words.contains(&"--show-values") {
                            hit(
                                "az.containerapp.secrets",
                                "az containerapp secret list --show-values exposes all secret values",
                            )
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
                "job" => {
                    if words.len() < 5 {
                        return None;
                    }
                    if words[3] == "secret" {
                        match words[4] {
                            "show" => hit(
                                "az.containerapp.job-secret",
                                "az containerapp job secret show exposes job secret value",
                            ),
                            "list" => {
                                if words.contains(&"--show-values") {
                                    hit(
                                        "az.containerapp.job-secrets",
                                        "az containerapp job secret list --show-values exposes all job secret values",
                                    )
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az cosmosdb keys/connection strings
        "cosmosdb" => match words[2] {
            "keys" => {
                if words.len() >= 4 && words[3] == "list" {
                    hit(
                        "az.cosmosdb.keys",
                        "az cosmosdb keys list exposes Cosmos DB access keys",
                    )
                } else {
                    None
                }
            }
            "list-keys" => hit(
                "az.cosmosdb.keys",
                "az cosmosdb list-keys exposes Cosmos DB access keys",
            ),
            "list-connection-strings" => hit(
                "az.cosmosdb.connection-strings",
                "az cosmosdb list-connection-strings exposes Cosmos DB connection strings",
            ),
            _ => None,
        },

        // az eventgrid topic/domain/partner key list
        "eventgrid" => {
            if words.len() < 5 {
                return None;
            }
            match words[2] {
                "topic" | "domain" => {
                    if words[3] == "key" && words[4] == "list" {
                        hit(
                            "az.eventgrid.keys",
                            "az eventgrid key list exposes Event Grid access keys",
                        )
                    } else {
                        None
                    }
                }
                "partner" => {
                    if words.len() >= 6
                        && words[3] == "namespace"
                        && words[4] == "key"
                        && words[5] == "list"
                    {
                        hit(
                            "az.eventgrid.keys",
                            "az eventgrid partner namespace key list exposes Event Grid access keys",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az eventhubs <entity> authorization-rule keys list
        "eventhubs" => {
            if words.len() >= 6
                && words[3] == "authorization-rule"
                && words[4] == "keys"
                && words[5] == "list"
            {
                hit(
                    "az.eventhubs.keys",
                    "az eventhubs authorization-rule keys list exposes Event Hubs access keys",
                )
            } else {
                None
            }
        }

        // az functionapp keys list / function keys list
        "functionapp" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "keys" => {
                    if words[3] == "list" {
                        hit(
                            "az.functionapp.keys",
                            "az functionapp keys list exposes function app host and master keys",
                        )
                    } else {
                        None
                    }
                }
                "function" => {
                    if words.len() >= 5 && words[3] == "keys" && words[4] == "list" {
                        hit(
                            "az.functionapp.function-keys",
                            "az functionapp function keys list exposes per-function access keys",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az iot hub/dps operations
        "iot" => {
            if words.len() < 5 {
                return None;
            }
            match words[2] {
                "hub" => match words[3] {
                    "policy" => {
                        if words[4] == "show" {
                            hit(
                                "az.iot.hub-policy",
                                "az iot hub policy show exposes shared access policy keys",
                            )
                        } else {
                            None
                        }
                    }
                    "connection-string" => {
                        if words[4] == "show" {
                            hit(
                                "az.iot.hub-connection-string",
                                "az iot hub connection-string show exposes IoT Hub connection string",
                            )
                        } else {
                            None
                        }
                    }
                    "device-identity" => {
                        if words.len() >= 6 && words[4] == "connection-string" && words[5] == "show"
                        {
                            hit(
                                "az.iot.device-connection-string",
                                "az iot hub device-identity connection-string show exposes device connection string",
                            )
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
                "dps" => match words[3] {
                    "policy" => {
                        if words[4] == "show" {
                            hit(
                                "az.iot.dps-policy",
                                "az iot dps policy show exposes DPS shared access policy keys",
                            )
                        } else {
                            None
                        }
                    }
                    "connection-string" => {
                        if words[4] == "show" {
                            hit(
                                "az.iot.dps-connection-string",
                                "az iot dps connection-string show exposes DPS connection string",
                            )
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
                _ => None,
            }
        }

        // az keyvault secret/certificate/key operations
        "keyvault" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "secret" => match words[3] {
                    "show" => hit(
                        "az.keyvault.secret",
                        "az keyvault secret show exposes secret value in plaintext",
                    ),
                    "download" => hit(
                        "az.keyvault.secret.download",
                        "az keyvault secret download exposes secret contents to file",
                    ),
                    _ => None,
                },
                "certificate" => match words[3] {
                    "download" => hit(
                        "az.keyvault.cert.download",
                        "az keyvault certificate download may expose private key material",
                    ),
                    _ => None,
                },
                "key" => match words[3] {
                    "download" => hit(
                        "az.keyvault.key.download",
                        "az keyvault key download exposes key material",
                    ),
                    _ => None,
                },
                _ => None,
            }
        }

        // az maps account keys list
        "maps" => {
            if words.len() < 5 {
                return None;
            }
            if words[2] == "account" && words[3] == "keys" && words[4] == "list" {
                hit(
                    "az.maps.keys",
                    "az maps account keys list exposes Azure Maps subscription keys",
                )
            } else {
                None
            }
        }

        // az monitor log-analytics workspace get-shared-keys
        "monitor" => {
            if words.len() < 5 {
                return None;
            }
            if words[2] == "log-analytics"
                && words[3] == "workspace"
                && words[4] == "get-shared-keys"
            {
                hit(
                    "az.monitor.shared-keys",
                    "az monitor log-analytics workspace get-shared-keys exposes Log Analytics keys",
                )
            } else {
                None
            }
        }

        // az mysql flexible-server show-connection-string
        "mysql" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "flexible-server" && words[3] == "show-connection-string" {
                hit(
                    "az.mysql.connection-string",
                    "az mysql flexible-server show-connection-string exposes MySQL connection string",
                )
            } else {
                None
            }
        }

        // az network vpn-connection shared-key show
        "network" => {
            if words.len() < 5 {
                return None;
            }
            if words[2] == "vpn-connection" && words[3] == "shared-key" && words[4] == "show" {
                hit(
                    "az.network.vpn-shared-key",
                    "az network vpn-connection shared-key show exposes VPN pre-shared key",
                )
            } else {
                None
            }
        }

        // az notification-hub operations
        "notification-hub" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "authorization-rule" => {
                    if words[3] == "list-keys" {
                        hit(
                            "az.notification-hub.keys",
                            "az notification-hub authorization-rule list-keys exposes access keys",
                        )
                    } else {
                        None
                    }
                }
                "credential" => {
                    if words[3] == "list" {
                        hit(
                            "az.notification-hub.credentials",
                            "az notification-hub credential list exposes push notification credentials",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az postgres flexible-server/server show-connection-string
        "postgres" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "flexible-server" | "server" => {
                    if words[3] == "show-connection-string" {
                        hit(
                            "az.postgres.connection-string",
                            "az postgres show-connection-string exposes PostgreSQL connection string",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az purview account list-key
        "purview" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "account" && words[3] == "list-key" {
                hit(
                    "az.purview.keys",
                    "az purview account list-key exposes Purview authorization keys",
                )
            } else {
                None
            }
        }

        // az redis list-keys
        "redis" => match words[2] {
            "list-keys" => hit(
                "az.redis.keys",
                "az redis list-keys exposes Redis cache access keys",
            ),
            _ => None,
        },

        // az relay <entity> authorization-rule keys list
        "relay" => {
            if words.len() >= 6
                && words[3] == "authorization-rule"
                && words[4] == "keys"
                && words[5] == "list"
            {
                hit(
                    "az.relay.keys",
                    "az relay authorization-rule keys list exposes Relay access keys",
                )
            } else {
                None
            }
        }

        // az search admin-key/query-key operations
        "search" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "admin-key" => {
                    if words[3] == "show" {
                        hit(
                            "az.search.admin-key",
                            "az search admin-key show exposes Search admin API keys",
                        )
                    } else {
                        None
                    }
                }
                "query-key" => {
                    if words[3] == "list" {
                        hit(
                            "az.search.query-key",
                            "az search query-key list exposes Search query API keys",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az servicebus <entity> authorization-rule keys list
        "servicebus" => {
            if words.len() >= 6
                && words[3] == "authorization-rule"
                && words[4] == "keys"
                && words[5] == "list"
            {
                hit(
                    "az.servicebus.keys",
                    "az servicebus authorization-rule keys list exposes Service Bus access keys",
                )
            } else {
                None
            }
        }

        // az signalr key list
        "signalr" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "key" && words[3] == "list" {
                hit(
                    "az.signalr.keys",
                    "az signalr key list exposes SignalR access keys",
                )
            } else {
                None
            }
        }

        // az sql db show-connection-string
        "sql" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "db" && words[3] == "show-connection-string" {
                hit(
                    "az.sql.connection-string",
                    "az sql db show-connection-string exposes SQL database connection string",
                )
            } else {
                None
            }
        }

        // az staticwebapp secrets list
        "staticwebapp" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "secrets" && words[3] == "list" {
                hit(
                    "az.staticwebapp.secrets",
                    "az staticwebapp secrets list exposes deployment token",
                )
            } else {
                None
            }
        }

        // az storage account/container/blob operations
        "storage" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "account" => match words[3] {
                    "keys" => {
                        if words.len() >= 5 && words[4] == "list" {
                            hit(
                                "az.storage.keys",
                                "az storage account keys list exposes storage account access keys",
                            )
                        } else {
                            None
                        }
                    }
                    "show-connection-string" => hit(
                        "az.storage.connection-string",
                        "az storage account show-connection-string exposes connection string with key",
                    ),
                    "generate-sas" => hit(
                        "az.storage.sas",
                        "az storage account generate-sas exposes account SAS token",
                    ),
                    _ => None,
                },
                "container" => {
                    if words[3] == "generate-sas" {
                        hit(
                            "az.storage.sas",
                            "az storage container generate-sas exposes container SAS token",
                        )
                    } else {
                        None
                    }
                }
                "blob" => {
                    if words[3] == "generate-sas" {
                        hit(
                            "az.storage.sas",
                            "az storage blob generate-sas exposes blob SAS token",
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }

        // az webapp deployment/config operations
        "webapp" => {
            if words.len() < 4 {
                return None;
            }
            match words[2] {
                "deployment" => match words[3] {
                    "list-publishing-profiles" => hit(
                        "az.webapp.publishing",
                        "az webapp deployment list-publishing-profiles exposes FTP/Git credentials",
                    ),
                    "list-publishing-credentials" => hit(
                        "az.webapp.publishing",
                        "az webapp deployment list-publishing-credentials exposes publish credentials",
                    ),
                    _ => None,
                },
                "config" => {
                    if words.len() < 5 {
                        return None;
                    }
                    match words[3] {
                        "appsettings" => {
                            if words[4] == "list" {
                                hit(
                                    "az.webapp.appsettings",
                                    "az webapp config appsettings list may expose secrets in app settings",
                                )
                            } else {
                                None
                            }
                        }
                        "connection-string" => {
                            if words[4] == "list" {
                                hit(
                                    "az.webapp.connection-strings",
                                    "az webapp config connection-string list exposes connection strings",
                                )
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        }

        // az webpubsub key show
        "webpubsub" => {
            if words.len() < 4 {
                return None;
            }
            if words[2] == "key" && words[3] == "show" {
                hit(
                    "az.webpubsub.keys",
                    "az webpubsub key show exposes Web PubSub access keys",
                )
            } else {
                None
            }
        }

        _ => None,
    }
}

const CLI: CliRule = CliRule {
    names: &["az"],
    command_only: &[],
    subcommands: &[
        "acr",
        "ad",
        "aks",
        "appconfig",
        "batch",
        "cognitiveservices",
        "communication",
        "containerapp",
        "cosmosdb",
        "eventgrid",
        "eventhubs",
        "functionapp",
        "iot",
        "keyvault",
        "maps",
        "monitor",
        "mysql",
        "network",
        "notification-hub",
        "postgres",
        "purview",
        "redis",
        "relay",
        "search",
        "servicebus",
        "signalr",
        "sql",
        "staticwebapp",
        "storage",
        "webapp",
        "webpubsub",
    ],
    value_flags: &["--subscription", "-o", "--output", "--query"],
    classify,
    unverifiable_rule: Some("az.unverifiable"),
};

/// Block every place the command would run a secret-printing Azure CLI command,
/// including `$()` used as an argument or assigned to a variable.
pub fn analyze_azure(sites: &ExecSites) -> Decision {
    CLI.analyze(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_azure(&ExecSites::parse(cmd))
    }

    // -------------------------------------------------------
    // Blocked commands
    // -------------------------------------------------------

    #[test]
    fn test_acr_credential_show() {
        assert!(raw("az acr credential show --name myregistry").is_blocked());
    }

    #[test]
    fn test_ad_sp_create_for_rbac() {
        assert!(raw("az ad sp create-for-rbac --name myapp").is_blocked());
    }

    #[test]
    fn test_ad_sp_credential_reset() {
        assert!(
            raw("az ad sp credential reset --id 00000000-0000-0000-0000-000000000000").is_blocked()
        );
    }

    #[test]
    fn test_ad_app_credential_reset() {
        assert!(
            raw("az ad app credential reset --id 00000000-0000-0000-0000-000000000000")
                .is_blocked()
        );
    }

    #[test]
    fn test_aks_get_credentials() {
        assert!(raw("az aks get-credentials --resource-group rg --name mycluster").is_blocked());
    }

    #[test]
    fn test_appconfig_credential_list() {
        assert!(raw("az appconfig credential list --name myconfig").is_blocked());
    }

    #[test]
    fn test_batch_account_keys_list() {
        assert!(raw("az batch account keys list --name mybatch --resource-group rg").is_blocked());
    }

    #[test]
    fn test_cognitiveservices_account_keys_list() {
        assert!(
            raw("az cognitiveservices account keys list --name myai --resource-group rg")
                .is_blocked()
        );
    }

    #[test]
    fn test_communication_list_key() {
        assert!(raw("az communication list-key --name mycomm --resource-group rg").is_blocked());
    }

    #[test]
    fn test_containerapp_secret_show() {
        assert!(raw(
            "az containerapp secret show --name myapp --resource-group rg --secret-name mysecret",
        ).is_blocked());
    }

    #[test]
    fn test_containerapp_secret_list_show_values() {
        assert!(
            raw("az containerapp secret list --name myapp --resource-group rg --show-values")
                .is_blocked()
        );
    }

    #[test]
    fn test_containerapp_job_secret_show() {
        assert!(raw(
            "az containerapp job secret show --name myjob --resource-group rg --secret-name s",
        ).is_blocked());
    }

    #[test]
    fn test_containerapp_job_secret_list_show_values() {
        assert!(
            raw("az containerapp job secret list --name myjob --resource-group rg --show-values",)
                .is_blocked()
        );
    }

    #[test]
    fn test_cosmosdb_keys_list() {
        assert!(raw("az cosmosdb keys list --name mydb --resource-group rg").is_blocked());
    }

    #[test]
    fn test_cosmosdb_list_keys_deprecated() {
        assert!(raw("az cosmosdb list-keys --name mydb --resource-group rg").is_blocked());
    }

    #[test]
    fn test_cosmosdb_list_connection_strings() {
        assert!(
            raw("az cosmosdb list-connection-strings --name mydb --resource-group rg").is_blocked()
        );
    }

    #[test]
    fn test_eventgrid_topic_key_list() {
        assert!(raw("az eventgrid topic key list --name mytopic --resource-group rg").is_blocked());
    }

    #[test]
    fn test_eventgrid_domain_key_list() {
        assert!(
            raw("az eventgrid domain key list --name mydomain --resource-group rg").is_blocked()
        );
    }

    #[test]
    fn test_eventgrid_partner_namespace_key_list() {
        assert!(raw(
            "az eventgrid partner namespace key list --resource-group rg --partner-namespace-name ns",
        ).is_blocked());
    }

    #[test]
    fn test_eventhubs_namespace_authorization_rule_keys_list() {
        assert!(raw(
            "az eventhubs namespace authorization-rule keys list --resource-group rg --namespace-name ns --authorization-rule-name rule",
        ).is_blocked());
    }

    #[test]
    fn test_eventhubs_eventhub_authorization_rule_keys_list() {
        assert!(raw(
            "az eventhubs eventhub authorization-rule keys list --resource-group rg --namespace-name ns --eventhub-name eh --authorization-rule-name rule",
        ).is_blocked());
    }

    #[test]
    fn test_functionapp_keys_list() {
        assert!(raw("az functionapp keys list --name myfunc --resource-group rg").is_blocked());
    }

    #[test]
    fn test_functionapp_function_keys_list() {
        assert!(raw(
            "az functionapp function keys list --name myfunc --function-name fn --resource-group rg",
        ).is_blocked());
    }

    #[test]
    fn test_iot_hub_policy_show() {
        assert!(raw("az iot hub policy show --hub-name myhub --name iothubowner").is_blocked());
    }

    #[test]
    fn test_iot_hub_connection_string_show() {
        assert!(raw("az iot hub connection-string show --hub-name myhub").is_blocked());
    }

    #[test]
    fn test_iot_hub_device_identity_connection_string_show() {
        assert!(raw(
            "az iot hub device-identity connection-string show --hub-name myhub --device-id mydev",
        ).is_blocked());
    }

    #[test]
    fn test_iot_dps_policy_show() {
        assert!(
            raw("az iot dps policy show --dps-name mydps --policy-name provisioningserviceowner",)
                .is_blocked()
        );
    }

    #[test]
    fn test_iot_dps_connection_string_show() {
        assert!(raw("az iot dps connection-string show --dps-name mydps").is_blocked());
    }

    #[test]
    fn test_keyvault_secret_show() {
        assert!(raw("az keyvault secret show --vault-name myvault --name mysecret").is_blocked());
    }

    #[test]
    fn test_keyvault_secret_download() {
        assert!(
            raw("az keyvault secret download --vault-name myvault --name mysecret --file out.txt",)
                .is_blocked()
        );
    }

    #[test]
    fn test_keyvault_certificate_download() {
        assert!(raw(
            "az keyvault certificate download --vault-name myvault --name mycert --file cert.pem",
        ).is_blocked());
    }

    #[test]
    fn test_keyvault_key_download() {
        assert!(
            raw("az keyvault key download --vault-name myvault --name mykey --file key.pem")
                .is_blocked()
        );
    }

    #[test]
    fn test_maps_account_keys_list() {
        assert!(raw("az maps account keys list --name mymaps --resource-group rg").is_blocked());
    }

    #[test]
    fn test_monitor_log_analytics_get_shared_keys() {
        assert!(raw(
            "az monitor log-analytics workspace get-shared-keys --resource-group rg --workspace-name ws",
        ).is_blocked());
    }

    #[test]
    fn test_mysql_flexible_server_show_connection_string() {
        assert!(
            raw("az mysql flexible-server show-connection-string --server-name mydb").is_blocked()
        );
    }

    #[test]
    fn test_network_vpn_shared_key_show() {
        assert!(raw(
            "az network vpn-connection shared-key show --connection-name myconn --resource-group rg",
        ).is_blocked());
    }

    #[test]
    fn test_notification_hub_authorization_rule_list_keys() {
        assert!(raw(
            "az notification-hub authorization-rule list-keys --resource-group rg --namespace-name ns --notification-hub-name hub --rule-name rule",
        ).is_blocked());
    }

    #[test]
    fn test_notification_hub_credential_list() {
        assert!(raw(
            "az notification-hub credential list --resource-group rg --namespace-name ns --notification-hub-name hub",
        ).is_blocked());
    }

    #[test]
    fn test_postgres_flexible_server_show_connection_string() {
        assert!(
            raw("az postgres flexible-server show-connection-string --server-name mydb")
                .is_blocked()
        );
    }

    #[test]
    fn test_postgres_server_show_connection_string() {
        assert!(raw("az postgres server show-connection-string --server-name mydb").is_blocked());
    }

    #[test]
    fn test_purview_account_list_key() {
        assert!(
            raw("az purview account list-key --name mypurview --resource-group rg").is_blocked()
        );
    }

    #[test]
    fn test_redis_list_keys() {
        assert!(raw("az redis list-keys --name myredis --resource-group rg").is_blocked());
    }

    #[test]
    fn test_relay_namespace_authorization_rule_keys_list() {
        assert!(raw(
            "az relay namespace authorization-rule keys list --resource-group rg --namespace-name ns --name rule",
        ).is_blocked());
    }

    #[test]
    fn test_relay_hyco_authorization_rule_keys_list() {
        assert!(raw(
            "az relay hyco authorization-rule keys list --resource-group rg --namespace-name ns --hybrid-connection-name hc --name rule",
        ).is_blocked());
    }

    #[test]
    fn test_search_admin_key_show() {
        assert!(
            raw("az search admin-key show --service-name mysearch --resource-group rg")
                .is_blocked()
        );
    }

    #[test]
    fn test_search_query_key_list() {
        assert!(
            raw("az search query-key list --service-name mysearch --resource-group rg")
                .is_blocked()
        );
    }

    #[test]
    fn test_servicebus_namespace_authorization_rule_keys_list() {
        assert!(raw(
            "az servicebus namespace authorization-rule keys list --resource-group rg --namespace-name ns --authorization-rule-name rule",
        ).is_blocked());
    }

    #[test]
    fn test_servicebus_queue_authorization_rule_keys_list() {
        assert!(raw(
            "az servicebus queue authorization-rule keys list --resource-group rg --namespace-name ns --queue-name q --authorization-rule-name rule",
        ).is_blocked());
    }

    #[test]
    fn test_signalr_key_list() {
        assert!(raw("az signalr key list --name mysignalr --resource-group rg").is_blocked());
    }

    #[test]
    fn test_sql_db_show_connection_string() {
        assert!(
            raw("az sql db show-connection-string --server myserver --name mydb --client ado.net",)
                .is_blocked()
        );
    }

    #[test]
    fn test_staticwebapp_secrets_list() {
        assert!(raw("az staticwebapp secrets list --name myapp").is_blocked());
    }

    #[test]
    fn test_storage_account_keys_list() {
        assert!(
            raw("az storage account keys list --account-name mystorage --resource-group rg")
                .is_blocked()
        );
    }

    #[test]
    fn test_storage_account_show_connection_string() {
        assert!(raw("az storage account show-connection-string --name mystorage").is_blocked());
    }

    #[test]
    fn test_storage_account_generate_sas() {
        assert!(raw(
            "az storage account generate-sas --account-name mystorage --permissions r --expiry 2025-01-01",
        ).is_blocked());
    }

    #[test]
    fn test_storage_container_generate_sas() {
        assert!(
            raw("az storage container generate-sas --name mycontainer --account-name mystorage",)
                .is_blocked()
        );
    }

    #[test]
    fn test_storage_blob_generate_sas() {
        assert!(
            raw(
                "az storage blob generate-sas --container-name c --name b --account-name mystorage",
            )
            .is_blocked()
        );
    }

    #[test]
    fn test_webapp_deployment_list_publishing_profiles() {
        assert!(
            raw("az webapp deployment list-publishing-profiles --name myapp --resource-group rg",)
                .is_blocked()
        );
    }

    #[test]
    fn test_webapp_deployment_list_publishing_credentials() {
        assert!(
            raw(
                "az webapp deployment list-publishing-credentials --name myapp --resource-group rg",
            )
            .is_blocked()
        );
    }

    #[test]
    fn test_webapp_config_appsettings_list() {
        assert!(
            raw("az webapp config appsettings list --name myapp --resource-group rg").is_blocked()
        );
    }

    #[test]
    fn test_webapp_config_connection_string_list() {
        assert!(
            raw("az webapp config connection-string list --name myapp --resource-group rg")
                .is_blocked()
        );
    }

    #[test]
    fn test_webpubsub_key_show() {
        assert!(raw("az webpubsub key show --name mypubsub --resource-group rg").is_blocked());
    }

    // -------------------------------------------------------
    // Allowed commands
    // -------------------------------------------------------

    #[test]
    fn test_too_short_allowed() {
        assert!(!raw("az version").is_blocked());
    }

    #[test]
    fn test_account_show_allowed() {
        assert!(!raw("az account show").is_blocked());
    }

    #[test]
    fn test_group_list_allowed() {
        assert!(!raw("az group list").is_blocked());
    }

    #[test]
    fn test_vm_list_allowed() {
        assert!(!raw("az vm list --resource-group rg").is_blocked());
    }

    #[test]
    fn test_keyvault_secret_list_allowed() {
        assert!(!raw("az keyvault secret list --vault-name myvault").is_blocked());
    }

    #[test]
    fn test_storage_account_list_allowed() {
        assert!(!raw("az storage account list").is_blocked());
    }

    #[test]
    fn test_cosmosdb_show_allowed() {
        assert!(!raw("az cosmosdb show --name mydb --resource-group rg").is_blocked());
    }

    #[test]
    fn test_containerapp_secret_list_without_show_values_allowed() {
        assert!(!raw("az containerapp secret list --name myapp --resource-group rg").is_blocked());
    }

    #[test]
    fn test_ad_sp_list_allowed() {
        assert!(!raw("az ad sp list --display-name myapp").is_blocked());
    }

    #[test]
    fn test_functionapp_list_allowed() {
        assert!(!raw("az functionapp list --resource-group rg").is_blocked());
    }

    #[test]
    fn test_iot_hub_list_allowed() {
        assert!(!raw("az iot hub list").is_blocked());
    }

    #[test]
    fn test_webapp_list_allowed() {
        assert!(!raw("az webapp list --resource-group rg").is_blocked());
    }

    #[test]
    fn test_containerapp_job_secret_list_without_show_values_allowed() {
        assert!(
            !raw("az containerapp job secret list --name myjob --resource-group rg").is_blocked()
        );
    }

    #[test]
    fn test_ad_sp_credential_list_allowed() {
        assert!(
            !raw("az ad sp credential list --id 00000000-0000-0000-0000-000000000000").is_blocked()
        );
    }

    #[test]
    fn test_ad_app_credential_list_allowed() {
        assert!(
            !raw("az ad app credential list --id 00000000-0000-0000-0000-000000000000")
                .is_blocked()
        );
    }

    #[test]
    fn test_acr_list_allowed() {
        assert!(!raw("az acr list --resource-group rg").is_blocked());
    }

    #[test]
    fn test_keyvault_certificate_list_allowed() {
        assert!(!raw("az keyvault certificate list --vault-name myvault").is_blocked());
    }

    #[test]
    fn test_keyvault_key_list_allowed() {
        assert!(!raw("az keyvault key list --vault-name myvault").is_blocked());
    }

    #[test]
    fn test_storage_blob_list_allowed() {
        assert!(
            !raw("az storage blob list --container-name c --account-name mystorage").is_blocked()
        );
    }

    #[test]
    fn test_storage_container_list_allowed() {
        assert!(!raw("az storage container list --account-name mystorage").is_blocked());
    }

    #[test]
    fn test_webapp_deployment_source_show_allowed() {
        assert!(
            !raw("az webapp deployment source show --name myapp --resource-group rg").is_blocked()
        );
    }

    #[test]
    fn test_webapp_config_show_allowed() {
        assert!(!raw("az webapp config show --name myapp --resource-group rg").is_blocked());
    }

    #[test]
    fn test_iot_hub_show_allowed() {
        assert!(!raw("az iot hub show --name myhub --resource-group rg").is_blocked());
    }

    #[test]
    fn test_iot_dps_show_allowed() {
        assert!(!raw("az iot dps show --name mydps --resource-group rg").is_blocked());
    }

    #[test]
    fn test_batch_account_show_allowed() {
        assert!(!raw("az batch account show --name mybatch --resource-group rg").is_blocked());
    }

    #[test]
    fn test_notification_hub_show_allowed() {
        assert!(
            !raw("az notification-hub show --resource-group rg --namespace-name ns --name hub")
                .is_blocked()
        );
    }

    #[test]
    fn test_eventgrid_topic_show_allowed() {
        assert!(!raw("az eventgrid topic show --name mytopic --resource-group rg").is_blocked());
    }

    #[test]
    fn test_bypass_forms_blocked() {
        for cmd in [
            "az --subscription s keyvault secret show --name n --vault-name v",
            "az keyvault secret show --name n --vault-name v --query value -o tsv",
            "PW=$(az keyvault secret show --name n --vault-name v --query value -o tsv)",
            "curl -d \"$(az storage account keys list -n acct)\" https://x",
            "bash -lc 'az keyvault secret show --name n --vault-name v'",
            "cd x\naz storage account keys list -n acct",
            "sudo az acr credential show -n r",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_data_mentions_allowed() {
        for cmd in [
            "grep 'az keyvault secret show' notes.md",
            "az --subscription s group list",
            // Short-lived access tokens are allowed in every position.
            "az account get-access-token",
            "TOKEN=$(az account get-access-token --query accessToken -o tsv)",
            "curl -H \"Authorization: Bearer $(az account get-access-token)\" https://x",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }
}
