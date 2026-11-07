resource "google_service_account" "agent" {
  account_id = "agent-runtime"
}

resource "google_project_iam_member" "agent_editor" {
  project = "acme-agents"
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.agent.email}"
}

resource "google_project_iam_member" "agent_logs" {
  project = "acme-agents"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.agent.email}"
}

resource "google_service_account_key" "agent" {
  service_account_id = google_service_account.agent.name
}

resource "azurerm_user_assigned_identity" "agent" {
  name                = "agent"
  location            = "japaneast"
  resource_group_name = "rg-agents"
}

resource "azurerm_role_assignment" "agent_owner" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-agents"
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}
