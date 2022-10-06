provider "google" {
  project = "cool-snowfall-196322"
  region = "us-west1"
  zone = "us-west1-a"
}

resource "google_storage_bucket" "test" {
  name = "hcltm-test"
  location = "US"
}

resource "google_compute_disk" "test" {
  name  = "hcltm-test-disk"
}

resource "google_sql_database_instance" "test" {
  name             = "hcltm-test-my-database-instance"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
  }

  deletion_protection  = "true"
}

resource "google_sql_database" "test" {
  name     = "hcltm-test-database"
  instance = google_sql_database_instance.test.name
}

resource "google_filestore_instance" "test" {
  name = "htlcm-test-instance"
  location = "us-central1-b"
  tier = "PREMIUM"

  file_shares {
    capacity_gb = 2660
    name        = "share1"
  }

  networks {
    network = "default"
    modes   = ["MODE_IPV4"]
  }
}

resource "google_artifact_registry_repository" "test" {
  location      = "us-central1"
  repository_id = "my-repository"
  description   = "example docker repository"
  format        = "DOCKER"
}
