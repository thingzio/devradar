# The Cloud SQL instance and the `thingz` database are owned by shared infra
# (thingzio/infra). DevRadar creates ONLY its own DB user — a separate login (and
# thus a separate connection pool) from DevPulse/DevTrace on the same instance.
# No instance, no database is created here.

data "google_sql_database_instance" "shared" {
  name    = var.db_instance_name
  project = var.project_id
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_user" "app" {
  name     = var.db_user
  instance = data.google_sql_database_instance.shared.name
  password = random_password.db_password.result
}
