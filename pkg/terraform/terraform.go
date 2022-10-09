package terraform

import (
	"encoding/json"
)

const tfJson = `
{"providers": {
  "aws": {
    "aws_s3_bucket": [
      "bucket",
      "bucket_prefix"
    ],
    "aws_rds_cluster": [
      "cluster_identifier",
      "cluster_identifier_prefix",
      "database_name"
    ],
		"aws_athena_database": [
			"name",
			"bucket"
		],
		"aws_dynamodb_table": [
			"name"
		],
		"aws_elasticache_cluster": [
			"cluster_id",
			"engine"
		],
		"aws_glacier_vault": [
			"name"
		],
		"aws_kms_key": [
			"description"
		],
		"aws_kms_alias": [
			"name",
			"name_prefix",
			"target_key_id"
		],
		"aws_qldb_ledger": [
			"name"
		],
		"aws_redshift_cluster": [
			"cluster_identifier",
			"database_name"
		],
		"aws_secretsmanager_secret": [
			"description",
			"name",
			"name_prefix",
			"kms_key_id"
		]
  },
	"google": {
		"google_storage_bucket": [
			"name",
			"location",
			"project"
		],
		"google_sql_database": [
			"name",
			"project"
		],
		"google_artifact_registry_repository": [
			"repository_id",
			"description",
			"format",
			"kms_key_name",
			"project"
		],
		"google_compute_disk": [
			"name",
			"project",
			"description",
			"disk_encryption_key"
		],
		"google_filestore_instance": [
			"name",
			"description",
			"project"
		],
		"google_bigquery_dataset": [
			"dataset_id",
			"description",
			"friendly_name",
			"project"
		],
		"google_bigquery_table": [
			"dataset_id",
			"table_id",
			"project",
			"description"
		]
	},
	"azurerm": {
		"azurerm_cosmosdb_cassandra_cluster": [
			"name"
		],
		"azurerm_cosmosdb_mongo_database": [
			"name"
		],
		"azurerm_cosmosdb_sql_database": [
			"name",
			"account_name"
		],
		"azurerm_data_share": [
			"name",
			"description"
		],
		"azurerm_key_vault": [
			"name"
		],
		"azurerm_mariadb_database": [
			"name",
			"server_name"
		],
		"azurerm_mssql_database": [
			"name"
		],
		"azurerm_mysql_server": [
			"name",
			"server_name"
		],
		"azurerm_postgresql_database": [
			"name",
			"server_name"
		],
		"azurerm_redis_cache": [
			"name"
		],
		"azurerm_storage_blob": [
			"name"
		],
		"azurerm_storage_container": [
			"name"
		],
		"azurerm_storage_share": [
			"name"
		]
	}
}}
`

type TfCollection map[string]TfProvider

type TfProvider struct {
	Name      string
	Resources map[string]TfResource
}

type TfResource struct {
	Attributes []string
}

func NewCollection() TfCollection {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(tfJson), &result)
	if err != nil {
		panic(err)
	}

	out := TfCollection{}

	provs := result["providers"].(map[string]interface{})

	for k, v := range provs {
		res := v.(map[string]interface{})

		newProv := TfProvider{
			Name:      k,
			Resources: map[string]TfResource{},
		}

		for rk, rv := range res {

			newRes := TfResource{}

			for _, av := range rv.([]interface{}) {
				newRes.Attributes = append(newRes.Attributes, av.(string))
			}

			newProv.Resources[rk] = newRes
		}

		out[k] = newProv
	}

	return out
}
