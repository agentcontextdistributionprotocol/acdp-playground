// Railway Infrastructure as Code for the acdp-playground service (project acdp-runner, production).
// Replaces railway.json (Config as Code, deprecated; stops applying 2026-12-01) - issue #119.
// The service deploys the ghcr image, so railway.json never applied to it; this file mirrors
// the live service as imported with `railway config pull` (no behaviour change).
// Needs Railway CLI >= 5:
//   railway config plan    # expect no changes
//   railway config apply
// Variables are unmanaged: they stay on the service and are never read or written here.
// Deploys still go through .github/workflows/deploy-images.yml (`railway redeploy --from-source`).
import { defineRailway, image, project, service } from "railway/iac";
// This repository manages only its own resources in the environment. Other
// repositories export their own partial name.
// See https://docs.railway.com/infrastructure-as-code#multi-repo-projects
export const partial = "acdp-playground";
const everyDay = [0, 1, 2, 3, 4, 5, 6].map((day) => ({ day, startHour: 0, endHour: 24 }));
export default defineRailway(() => {
  const acdpPlayground = service("acdp-playground", {
    source: image("ghcr.io/agentcontextdistributionprotocol/acdp-playground:latest", {
      autoUpdates: { schedule: everyDay, type: "patch" },
    }),
    build: { buildEnvironment: "V3", builder: "RAILPACK" },
    // Health check + restart policy (the old railway.json declared these, but the
    // image-sourced service never read it, so they first go live here).
    deploy: {
      healthcheckPath: "/healthz",
      healthcheckTimeout: 120,
      restartPolicyType: "ON_FAILURE",
      restartPolicyMaxRetries: 10,
    },
    replicas: { "us-west2": 1 },
  });

  return project("acdp-runner", {
    variables: { managed: false },
    resources: [acdpPlayground],
  });
});
