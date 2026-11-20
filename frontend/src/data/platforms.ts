export type PlatformStatus = "active" | "limited" | "planned";

export type Platform = {
  id: string;
  name: string;
  phase: number;
  status: PlatformStatus;
  covers: string[];
};

// Power Automate cloud flows and AI agent / MCP configuration files are working. Everything marked planned is a roadmap entry.
export const PLATFORMS: Platform[] = [
  { id: "power-platform", name: "Microsoft Power Platform", phase: 1, status: "active",
    covers: ["Power Automate cloud flows (active)", "Power Automate desktop flows", "Power Apps", "Connectors", "Environment configurations"] },
  { id: "uipath", name: "UiPath", phase: 2, status: "active",
    covers: ["Studio workflows, .xaml (active)", "project.json: dependencies, logging, framework (active)", "Credential-handling patterns (active)",
      "Activities: HTTP, code, SQL, logging (active)", "Packages, .nupkg (active)", "Orchestrator assets and robot configuration (planned)"] },
  { id: "other-rpa", name: "Other RPA platforms", phase: 3, status: "limited",
    covers: ["Automation Anywhere .bot / .atmx: basic checks (limited)", "Blue Prism .bprelease / .bpobject / .bpprocess: basic checks (limited)",
      "Full vendor-specific checks need real export samples (planned)"] },
  { id: "ai-agents", name: "AI and agentic automation", phase: 4, status: "active",
    covers: ["MCP server configurations (active)", "Agent definition files: tools, permissions, tool calling (active)",
      "Prompt-injection and data-exposure paths, heuristic (active)", "Sensitive data in prompts and config (active)",
      "Agent-to-agent delegation (active)", "Copilot Studio exports (planned)", "Runtime and live testing (planned)"] },
];
