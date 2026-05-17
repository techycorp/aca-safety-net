//! Azure CLI analysis - blocks commands that expose secrets.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze Azure CLI commands for secret exposure.
pub fn analyze_azure(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.len() < 3 {
        return Decision::allow();
    }

    // Azure CLI structure: az <group> [subgroup...] <command> [options]
    let group = words[1];

    match group {
        // az account get-access-token
        "account" => match words[2] {
            "get-access-token" => Decision::block(
                "az.account.token",
                "az account get-access-token exposes OAuth2 access token",
            ),
            _ => Decision::allow(),
        },

        // az acr credential show
        "acr" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "credential" && words[3] == "show" {
                Decision::block(
                    "az.acr.credentials",
                    "az acr credential show exposes container registry credentials",
                )
            } else {
                Decision::allow()
            }
        }

        // az ad sp/app credential operations
        "ad" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "sp" => match words[3] {
                    "create-for-rbac" => Decision::block(
                        "az.ad.sp.create",
                        "az ad sp create-for-rbac exposes new service principal credentials",
                    ),
                    "credential" => {
                        if words.len() >= 5 && words[4] == "reset" {
                            Decision::block(
                                "az.ad.sp.credential-reset",
                                "az ad sp credential reset exposes new service principal password",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    _ => Decision::allow(),
                },
                "app" => {
                    if words[3] == "credential" && words.len() >= 5 && words[4] == "reset" {
                        Decision::block(
                            "az.ad.app.credential-reset",
                            "az ad app credential reset exposes new app client secret",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az aks get-credentials
        "aks" => match words[2] {
            "get-credentials" => Decision::block(
                "az.aks.credentials",
                "az aks get-credentials exposes Kubernetes cluster credentials",
            ),
            _ => Decision::allow(),
        },

        // az appconfig credential list
        "appconfig" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "credential" && words[3] == "list" {
                Decision::block(
                    "az.appconfig.credentials",
                    "az appconfig credential list exposes App Configuration access keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az batch account keys list
        "batch" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            if words[2] == "account" && words[3] == "keys" && words[4] == "list" {
                Decision::block(
                    "az.batch.keys",
                    "az batch account keys list exposes Batch account access keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az cognitiveservices account keys list
        "cognitiveservices" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            if words[2] == "account" && words[3] == "keys" && words[4] == "list" {
                Decision::block(
                    "az.cognitiveservices.keys",
                    "az cognitiveservices account keys list exposes API keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az communication list-key
        "communication" => match words[2] {
            "list-key" => Decision::block(
                "az.communication.keys",
                "az communication list-key exposes Communication Services access keys",
            ),
            _ => Decision::allow(),
        },

        // az containerapp secret/job operations
        "containerapp" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "secret" => match words[3] {
                    "show" => Decision::block(
                        "az.containerapp.secret",
                        "az containerapp secret show exposes secret value",
                    ),
                    "list" => {
                        if words.contains(&"--show-values") {
                            Decision::block(
                                "az.containerapp.secrets",
                                "az containerapp secret list --show-values exposes all secret values",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    _ => Decision::allow(),
                },
                "job" => {
                    if words.len() < 5 {
                        return Decision::allow();
                    }
                    if words[3] == "secret" {
                        match words[4] {
                            "show" => Decision::block(
                                "az.containerapp.job-secret",
                                "az containerapp job secret show exposes job secret value",
                            ),
                            "list" => {
                                if words.contains(&"--show-values") {
                                    Decision::block(
                                        "az.containerapp.job-secrets",
                                        "az containerapp job secret list --show-values exposes all job secret values",
                                    )
                                } else {
                                    Decision::allow()
                                }
                            }
                            _ => Decision::allow(),
                        }
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az cosmosdb keys/connection strings
        "cosmosdb" => match words[2] {
            "keys" => {
                if words.len() >= 4 && words[3] == "list" {
                    Decision::block(
                        "az.cosmosdb.keys",
                        "az cosmosdb keys list exposes Cosmos DB access keys",
                    )
                } else {
                    Decision::allow()
                }
            }
            "list-keys" => Decision::block(
                "az.cosmosdb.keys",
                "az cosmosdb list-keys exposes Cosmos DB access keys",
            ),
            "list-connection-strings" => Decision::block(
                "az.cosmosdb.connection-strings",
                "az cosmosdb list-connection-strings exposes Cosmos DB connection strings",
            ),
            _ => Decision::allow(),
        },

        // az eventgrid topic/domain/partner key list
        "eventgrid" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            match words[2] {
                "topic" | "domain" => {
                    if words[3] == "key" && words[4] == "list" {
                        Decision::block(
                            "az.eventgrid.keys",
                            "az eventgrid key list exposes Event Grid access keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                "partner" => {
                    if words.len() >= 6
                        && words[3] == "namespace"
                        && words[4] == "key"
                        && words[5] == "list"
                    {
                        Decision::block(
                            "az.eventgrid.keys",
                            "az eventgrid partner namespace key list exposes Event Grid access keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az eventhubs <entity> authorization-rule keys list
        "eventhubs" => {
            if words.len() >= 6
                && words[3] == "authorization-rule"
                && words[4] == "keys"
                && words[5] == "list"
            {
                Decision::block(
                    "az.eventhubs.keys",
                    "az eventhubs authorization-rule keys list exposes Event Hubs access keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az functionapp keys list / function keys list
        "functionapp" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "keys" => {
                    if words[3] == "list" {
                        Decision::block(
                            "az.functionapp.keys",
                            "az functionapp keys list exposes function app host and master keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                "function" => {
                    if words.len() >= 5 && words[3] == "keys" && words[4] == "list" {
                        Decision::block(
                            "az.functionapp.function-keys",
                            "az functionapp function keys list exposes per-function access keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az iot hub/dps operations
        "iot" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            match words[2] {
                "hub" => match words[3] {
                    "policy" => {
                        if words[4] == "show" {
                            Decision::block(
                                "az.iot.hub-policy",
                                "az iot hub policy show exposes shared access policy keys",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    "connection-string" => {
                        if words[4] == "show" {
                            Decision::block(
                                "az.iot.hub-connection-string",
                                "az iot hub connection-string show exposes IoT Hub connection string",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    "device-identity" => {
                        if words.len() >= 6 && words[4] == "connection-string" && words[5] == "show"
                        {
                            Decision::block(
                                "az.iot.device-connection-string",
                                "az iot hub device-identity connection-string show exposes device connection string",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    _ => Decision::allow(),
                },
                "dps" => match words[3] {
                    "policy" => {
                        if words[4] == "show" {
                            Decision::block(
                                "az.iot.dps-policy",
                                "az iot dps policy show exposes DPS shared access policy keys",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    "connection-string" => {
                        if words[4] == "show" {
                            Decision::block(
                                "az.iot.dps-connection-string",
                                "az iot dps connection-string show exposes DPS connection string",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    _ => Decision::allow(),
                },
                _ => Decision::allow(),
            }
        }

        // az keyvault secret/certificate/key operations
        "keyvault" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "secret" => match words[3] {
                    "show" => Decision::block(
                        "az.keyvault.secret",
                        "az keyvault secret show exposes secret value in plaintext",
                    ),
                    "download" => Decision::block(
                        "az.keyvault.secret.download",
                        "az keyvault secret download exposes secret contents to file",
                    ),
                    _ => Decision::allow(),
                },
                "certificate" => match words[3] {
                    "download" => Decision::block(
                        "az.keyvault.cert.download",
                        "az keyvault certificate download may expose private key material",
                    ),
                    _ => Decision::allow(),
                },
                "key" => match words[3] {
                    "download" => Decision::block(
                        "az.keyvault.key.download",
                        "az keyvault key download exposes key material",
                    ),
                    _ => Decision::allow(),
                },
                _ => Decision::allow(),
            }
        }

        // az maps account keys list
        "maps" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            if words[2] == "account" && words[3] == "keys" && words[4] == "list" {
                Decision::block(
                    "az.maps.keys",
                    "az maps account keys list exposes Azure Maps subscription keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az monitor log-analytics workspace get-shared-keys
        "monitor" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            if words[2] == "log-analytics"
                && words[3] == "workspace"
                && words[4] == "get-shared-keys"
            {
                Decision::block(
                    "az.monitor.shared-keys",
                    "az monitor log-analytics workspace get-shared-keys exposes Log Analytics keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az mysql flexible-server show-connection-string
        "mysql" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "flexible-server" && words[3] == "show-connection-string" {
                Decision::block(
                    "az.mysql.connection-string",
                    "az mysql flexible-server show-connection-string exposes MySQL connection string",
                )
            } else {
                Decision::allow()
            }
        }

        // az network vpn-connection shared-key show
        "network" => {
            if words.len() < 5 {
                return Decision::allow();
            }
            if words[2] == "vpn-connection" && words[3] == "shared-key" && words[4] == "show" {
                Decision::block(
                    "az.network.vpn-shared-key",
                    "az network vpn-connection shared-key show exposes VPN pre-shared key",
                )
            } else {
                Decision::allow()
            }
        }

        // az notification-hub operations
        "notification-hub" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "authorization-rule" => {
                    if words[3] == "list-keys" {
                        Decision::block(
                            "az.notification-hub.keys",
                            "az notification-hub authorization-rule list-keys exposes access keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                "credential" => {
                    if words[3] == "list" {
                        Decision::block(
                            "az.notification-hub.credentials",
                            "az notification-hub credential list exposes push notification credentials",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az postgres flexible-server/server show-connection-string
        "postgres" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "flexible-server" | "server" => {
                    if words[3] == "show-connection-string" {
                        Decision::block(
                            "az.postgres.connection-string",
                            "az postgres show-connection-string exposes PostgreSQL connection string",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az purview account list-key
        "purview" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "account" && words[3] == "list-key" {
                Decision::block(
                    "az.purview.keys",
                    "az purview account list-key exposes Purview authorization keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az redis list-keys
        "redis" => match words[2] {
            "list-keys" => Decision::block(
                "az.redis.keys",
                "az redis list-keys exposes Redis cache access keys",
            ),
            _ => Decision::allow(),
        },

        // az relay <entity> authorization-rule keys list
        "relay" => {
            if words.len() >= 6
                && words[3] == "authorization-rule"
                && words[4] == "keys"
                && words[5] == "list"
            {
                Decision::block(
                    "az.relay.keys",
                    "az relay authorization-rule keys list exposes Relay access keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az search admin-key/query-key operations
        "search" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "admin-key" => {
                    if words[3] == "show" {
                        Decision::block(
                            "az.search.admin-key",
                            "az search admin-key show exposes Search admin API keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                "query-key" => {
                    if words[3] == "list" {
                        Decision::block(
                            "az.search.query-key",
                            "az search query-key list exposes Search query API keys",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az servicebus <entity> authorization-rule keys list
        "servicebus" => {
            if words.len() >= 6
                && words[3] == "authorization-rule"
                && words[4] == "keys"
                && words[5] == "list"
            {
                Decision::block(
                    "az.servicebus.keys",
                    "az servicebus authorization-rule keys list exposes Service Bus access keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az signalr key list
        "signalr" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "key" && words[3] == "list" {
                Decision::block(
                    "az.signalr.keys",
                    "az signalr key list exposes SignalR access keys",
                )
            } else {
                Decision::allow()
            }
        }

        // az sql db show-connection-string
        "sql" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "db" && words[3] == "show-connection-string" {
                Decision::block(
                    "az.sql.connection-string",
                    "az sql db show-connection-string exposes SQL database connection string",
                )
            } else {
                Decision::allow()
            }
        }

        // az staticwebapp secrets list
        "staticwebapp" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "secrets" && words[3] == "list" {
                Decision::block(
                    "az.staticwebapp.secrets",
                    "az staticwebapp secrets list exposes deployment token",
                )
            } else {
                Decision::allow()
            }
        }

        // az storage account/container/blob operations
        "storage" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "account" => match words[3] {
                    "keys" => {
                        if words.len() >= 5 && words[4] == "list" {
                            Decision::block(
                                "az.storage.keys",
                                "az storage account keys list exposes storage account access keys",
                            )
                        } else {
                            Decision::allow()
                        }
                    }
                    "show-connection-string" => Decision::block(
                        "az.storage.connection-string",
                        "az storage account show-connection-string exposes connection string with key",
                    ),
                    "generate-sas" => Decision::block(
                        "az.storage.sas",
                        "az storage account generate-sas exposes account SAS token",
                    ),
                    _ => Decision::allow(),
                },
                "container" => {
                    if words[3] == "generate-sas" {
                        Decision::block(
                            "az.storage.sas",
                            "az storage container generate-sas exposes container SAS token",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                "blob" => {
                    if words[3] == "generate-sas" {
                        Decision::block(
                            "az.storage.sas",
                            "az storage blob generate-sas exposes blob SAS token",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az webapp deployment/config operations
        "webapp" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            match words[2] {
                "deployment" => match words[3] {
                    "list-publishing-profiles" => Decision::block(
                        "az.webapp.publishing",
                        "az webapp deployment list-publishing-profiles exposes FTP/Git credentials",
                    ),
                    "list-publishing-credentials" => Decision::block(
                        "az.webapp.publishing",
                        "az webapp deployment list-publishing-credentials exposes publish credentials",
                    ),
                    _ => Decision::allow(),
                },
                "config" => {
                    if words.len() < 5 {
                        return Decision::allow();
                    }
                    match words[3] {
                        "appsettings" => {
                            if words[4] == "list" {
                                Decision::block(
                                    "az.webapp.appsettings",
                                    "az webapp config appsettings list may expose secrets in app settings",
                                )
                            } else {
                                Decision::allow()
                            }
                        }
                        "connection-string" => {
                            if words[4] == "list" {
                                Decision::block(
                                    "az.webapp.connection-strings",
                                    "az webapp config connection-string list exposes connection strings",
                                )
                            } else {
                                Decision::allow()
                            }
                        }
                        _ => Decision::allow(),
                    }
                }
                _ => Decision::allow(),
            }
        }

        // az webpubsub key show
        "webpubsub" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            if words[2] == "key" && words[3] == "show" {
                Decision::block(
                    "az.webpubsub.keys",
                    "az webpubsub key show exposes Web PubSub access keys",
                )
            } else {
                Decision::allow()
            }
        }

        _ => Decision::allow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::shell::tokenize;

    fn test_config() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    // -------------------------------------------------------
    // Blocked commands
    // -------------------------------------------------------

    #[test]
    fn test_account_get_access_token() {
        let config = test_config();
        let tokens = tokenize("az account get-access-token");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_acr_credential_show() {
        let config = test_config();
        let tokens = tokenize("az acr credential show --name myregistry");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_ad_sp_create_for_rbac() {
        let config = test_config();
        let tokens = tokenize("az ad sp create-for-rbac --name myapp");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_ad_sp_credential_reset() {
        let config = test_config();
        let tokens =
            tokenize("az ad sp credential reset --id 00000000-0000-0000-0000-000000000000");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_ad_app_credential_reset() {
        let config = test_config();
        let tokens =
            tokenize("az ad app credential reset --id 00000000-0000-0000-0000-000000000000");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_aks_get_credentials() {
        let config = test_config();
        let tokens = tokenize("az aks get-credentials --resource-group rg --name mycluster");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_appconfig_credential_list() {
        let config = test_config();
        let tokens = tokenize("az appconfig credential list --name myconfig");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_batch_account_keys_list() {
        let config = test_config();
        let tokens = tokenize("az batch account keys list --name mybatch --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_cognitiveservices_account_keys_list() {
        let config = test_config();
        let tokens =
            tokenize("az cognitiveservices account keys list --name myai --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_communication_list_key() {
        let config = test_config();
        let tokens = tokenize("az communication list-key --name mycomm --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_containerapp_secret_show() {
        let config = test_config();
        let tokens = tokenize(
            "az containerapp secret show --name myapp --resource-group rg --secret-name mysecret",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_containerapp_secret_list_show_values() {
        let config = test_config();
        let tokens =
            tokenize("az containerapp secret list --name myapp --resource-group rg --show-values");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_containerapp_job_secret_show() {
        let config = test_config();
        let tokens = tokenize(
            "az containerapp job secret show --name myjob --resource-group rg --secret-name s",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_containerapp_job_secret_list_show_values() {
        let config = test_config();
        let tokens = tokenize(
            "az containerapp job secret list --name myjob --resource-group rg --show-values",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_cosmosdb_keys_list() {
        let config = test_config();
        let tokens = tokenize("az cosmosdb keys list --name mydb --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_cosmosdb_list_keys_deprecated() {
        let config = test_config();
        let tokens = tokenize("az cosmosdb list-keys --name mydb --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_cosmosdb_list_connection_strings() {
        let config = test_config();
        let tokens =
            tokenize("az cosmosdb list-connection-strings --name mydb --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_eventgrid_topic_key_list() {
        let config = test_config();
        let tokens = tokenize("az eventgrid topic key list --name mytopic --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_eventgrid_domain_key_list() {
        let config = test_config();
        let tokens = tokenize("az eventgrid domain key list --name mydomain --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_eventgrid_partner_namespace_key_list() {
        let config = test_config();
        let tokens = tokenize(
            "az eventgrid partner namespace key list --resource-group rg --partner-namespace-name ns",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_eventhubs_namespace_authorization_rule_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az eventhubs namespace authorization-rule keys list --resource-group rg --namespace-name ns --authorization-rule-name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_eventhubs_eventhub_authorization_rule_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az eventhubs eventhub authorization-rule keys list --resource-group rg --namespace-name ns --eventhub-name eh --authorization-rule-name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_functionapp_keys_list() {
        let config = test_config();
        let tokens = tokenize("az functionapp keys list --name myfunc --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_functionapp_function_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az functionapp function keys list --name myfunc --function-name fn --resource-group rg",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_hub_policy_show() {
        let config = test_config();
        let tokens = tokenize("az iot hub policy show --hub-name myhub --name iothubowner");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_hub_connection_string_show() {
        let config = test_config();
        let tokens = tokenize("az iot hub connection-string show --hub-name myhub");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_hub_device_identity_connection_string_show() {
        let config = test_config();
        let tokens = tokenize(
            "az iot hub device-identity connection-string show --hub-name myhub --device-id mydev",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_dps_policy_show() {
        let config = test_config();
        let tokens = tokenize(
            "az iot dps policy show --dps-name mydps --policy-name provisioningserviceowner",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_dps_connection_string_show() {
        let config = test_config();
        let tokens = tokenize("az iot dps connection-string show --dps-name mydps");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_secret_show() {
        let config = test_config();
        let tokens = tokenize("az keyvault secret show --vault-name myvault --name mysecret");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_secret_download() {
        let config = test_config();
        let tokens = tokenize(
            "az keyvault secret download --vault-name myvault --name mysecret --file out.txt",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_certificate_download() {
        let config = test_config();
        let tokens = tokenize(
            "az keyvault certificate download --vault-name myvault --name mycert --file cert.pem",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_key_download() {
        let config = test_config();
        let tokens =
            tokenize("az keyvault key download --vault-name myvault --name mykey --file key.pem");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_maps_account_keys_list() {
        let config = test_config();
        let tokens = tokenize("az maps account keys list --name mymaps --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_monitor_log_analytics_get_shared_keys() {
        let config = test_config();
        let tokens = tokenize(
            "az monitor log-analytics workspace get-shared-keys --resource-group rg --workspace-name ws",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_mysql_flexible_server_show_connection_string() {
        let config = test_config();
        let tokens = tokenize("az mysql flexible-server show-connection-string --server-name mydb");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_network_vpn_shared_key_show() {
        let config = test_config();
        let tokens = tokenize(
            "az network vpn-connection shared-key show --connection-name myconn --resource-group rg",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_notification_hub_authorization_rule_list_keys() {
        let config = test_config();
        let tokens = tokenize(
            "az notification-hub authorization-rule list-keys --resource-group rg --namespace-name ns --notification-hub-name hub --rule-name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_notification_hub_credential_list() {
        let config = test_config();
        let tokens = tokenize(
            "az notification-hub credential list --resource-group rg --namespace-name ns --notification-hub-name hub",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_postgres_flexible_server_show_connection_string() {
        let config = test_config();
        let tokens =
            tokenize("az postgres flexible-server show-connection-string --server-name mydb");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_postgres_server_show_connection_string() {
        let config = test_config();
        let tokens = tokenize("az postgres server show-connection-string --server-name mydb");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_purview_account_list_key() {
        let config = test_config();
        let tokens = tokenize("az purview account list-key --name mypurview --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_redis_list_keys() {
        let config = test_config();
        let tokens = tokenize("az redis list-keys --name myredis --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_relay_namespace_authorization_rule_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az relay namespace authorization-rule keys list --resource-group rg --namespace-name ns --name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_relay_hyco_authorization_rule_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az relay hyco authorization-rule keys list --resource-group rg --namespace-name ns --hybrid-connection-name hc --name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_search_admin_key_show() {
        let config = test_config();
        let tokens =
            tokenize("az search admin-key show --service-name mysearch --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_search_query_key_list() {
        let config = test_config();
        let tokens =
            tokenize("az search query-key list --service-name mysearch --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_servicebus_namespace_authorization_rule_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az servicebus namespace authorization-rule keys list --resource-group rg --namespace-name ns --authorization-rule-name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_servicebus_queue_authorization_rule_keys_list() {
        let config = test_config();
        let tokens = tokenize(
            "az servicebus queue authorization-rule keys list --resource-group rg --namespace-name ns --queue-name q --authorization-rule-name rule",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_signalr_key_list() {
        let config = test_config();
        let tokens = tokenize("az signalr key list --name mysignalr --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_sql_db_show_connection_string() {
        let config = test_config();
        let tokens = tokenize(
            "az sql db show-connection-string --server myserver --name mydb --client ado.net",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_staticwebapp_secrets_list() {
        let config = test_config();
        let tokens = tokenize("az staticwebapp secrets list --name myapp");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_account_keys_list() {
        let config = test_config();
        let tokens =
            tokenize("az storage account keys list --account-name mystorage --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_account_show_connection_string() {
        let config = test_config();
        let tokens = tokenize("az storage account show-connection-string --name mystorage");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_account_generate_sas() {
        let config = test_config();
        let tokens = tokenize(
            "az storage account generate-sas --account-name mystorage --permissions r --expiry 2025-01-01",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_container_generate_sas() {
        let config = test_config();
        let tokens = tokenize(
            "az storage container generate-sas --name mycontainer --account-name mystorage",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_blob_generate_sas() {
        let config = test_config();
        let tokens = tokenize(
            "az storage blob generate-sas --container-name c --name b --account-name mystorage",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_deployment_list_publishing_profiles() {
        let config = test_config();
        let tokens = tokenize(
            "az webapp deployment list-publishing-profiles --name myapp --resource-group rg",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_deployment_list_publishing_credentials() {
        let config = test_config();
        let tokens = tokenize(
            "az webapp deployment list-publishing-credentials --name myapp --resource-group rg",
        );
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_config_appsettings_list() {
        let config = test_config();
        let tokens = tokenize("az webapp config appsettings list --name myapp --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_config_connection_string_list() {
        let config = test_config();
        let tokens =
            tokenize("az webapp config connection-string list --name myapp --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webpubsub_key_show() {
        let config = test_config();
        let tokens = tokenize("az webpubsub key show --name mypubsub --resource-group rg");
        assert!(analyze_azure(&tokens, &config).is_blocked());
    }

    // -------------------------------------------------------
    // Allowed commands
    // -------------------------------------------------------

    #[test]
    fn test_too_short_allowed() {
        let config = test_config();
        let tokens = tokenize("az version");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_account_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az account show");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_group_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az group list");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_vm_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az vm list --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_secret_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az keyvault secret list --vault-name myvault");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_account_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az storage account list");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_cosmosdb_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az cosmosdb show --name mydb --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_containerapp_secret_list_without_show_values_allowed() {
        let config = test_config();
        let tokens = tokenize("az containerapp secret list --name myapp --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_ad_sp_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az ad sp list --display-name myapp");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_functionapp_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az functionapp list --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_hub_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az iot hub list");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az webapp list --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_containerapp_job_secret_list_without_show_values_allowed() {
        let config = test_config();
        let tokens = tokenize("az containerapp job secret list --name myjob --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_ad_sp_credential_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az ad sp credential list --id 00000000-0000-0000-0000-000000000000");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_ad_app_credential_list_allowed() {
        let config = test_config();
        let tokens =
            tokenize("az ad app credential list --id 00000000-0000-0000-0000-000000000000");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_acr_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az acr list --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_certificate_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az keyvault certificate list --vault-name myvault");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_keyvault_key_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az keyvault key list --vault-name myvault");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_blob_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az storage blob list --container-name c --account-name mystorage");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_storage_container_list_allowed() {
        let config = test_config();
        let tokens = tokenize("az storage container list --account-name mystorage");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_deployment_source_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az webapp deployment source show --name myapp --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_webapp_config_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az webapp config show --name myapp --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_hub_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az iot hub show --name myhub --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_iot_dps_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az iot dps show --name mydps --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_batch_account_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az batch account show --name mybatch --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_notification_hub_show_allowed() {
        let config = test_config();
        let tokens =
            tokenize("az notification-hub show --resource-group rg --namespace-name ns --name hub");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }

    #[test]
    fn test_eventgrid_topic_show_allowed() {
        let config = test_config();
        let tokens = tokenize("az eventgrid topic show --name mytopic --resource-group rg");
        assert!(!analyze_azure(&tokens, &config).is_blocked());
    }
}
