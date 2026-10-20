import "@mantine/core/styles.css";
import "@mantine/code-highlight/styles.css";
import "@mantine/notifications/styles.css";
import "@mantine/dates/styles.css";
import "./mantine-overrides.css";

import {
  AppShell,
  Box,
  Burger,
  Group,
  MantineProvider,
  Skeleton,
  Text,
  createTheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  BrowserRouter,
  Link,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import QueryPage from "./pages/query/QueryPage";
import AgentPage from "./pages/AgentPage";
import { Suspense } from "react";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeSelector } from "./components/ThemeSelector";
import { Notifications } from "@mantine/notifications";
import { useSettings } from "./state/settingsSlice";
import SettingsMenu from "./components/SettingsMenu";
import ReadinessWrapper from "./components/ReadinessWrapper";
// MAIA: NotificationsProvider/Icon disabled — they open /api/v1/notifications/live SSE
import { QueryParamProvider } from "use-query-params";
import { ReactRouter6Adapter } from "use-query-params/adapters/react-router-6";
// MAIA: project context provider and switcher
import { MaiaProjectProvider } from "./context/MaiaProjectContext";
import { MaiaProjectSwitcher } from "./components/MaiaProjectSwitcher";

import {
  CodeHighlightAdapterProvider,
  createHighlightJsAdapter,
} from "@mantine/code-highlight";
import hljs from "highlight.js/lib/core";
import "./highlightjs.css";
import yamlLang from "highlight.js/lib/languages/yaml";

hljs.registerLanguage("yaml", yamlLang);

const highlightJsAdapter = createHighlightJsAdapter(hljs);
const queryClient = new QueryClient();

const theme = createTheme({
  // Preserve v8 default border-radius for now (was 'sm' in v8, changed to 'md' in v9).
  defaultRadius: "sm",
  colors: {
    "codebox-bg": [
      "#f5f5f5", "#e7e7e7", "#cdcdcd", "#b2b2b2", "#9a9a9a",
      "#8b8b8b", "#848484", "#717171", "#656565", "#575757",
    ],
  },
});

function App() {
  const [opened, { toggle }] = useDisclosure();
  const { agentMode, pathPrefix } = useSettings();

  const navActionIcons = (
    <>
      <ThemeSelector />
      {/* MAIA: NotificationsIcon removed — triggers /api/v1/notifications/live SSE */}
      <SettingsMenu />
    </>
  );

  return (
    <BrowserRouter basename={pathPrefix}>
      <QueryParamProvider adapter={ReactRouter6Adapter}>
        <MantineProvider defaultColorScheme="auto" theme={theme}>
          <CodeHighlightAdapterProvider adapter={highlightJsAdapter}>
            <Notifications position="top-right" />
            <QueryClientProvider client={queryClient}>
              {/* MAIA: wrap with project provider — exposes currentProject to all children */}
              <MaiaProjectProvider>
                <AppShell
                  header={{ height: 56 }}
                  navbar={{
                    width: 300,
                    breakpoint: "sm",
                    collapsed: { desktop: true, mobile: !opened },
                  }}
                  padding="md"
                >
                  <AppShell.Header bg="rgb(65, 73, 81)" c="#fff">
                    <Group h={56} px="md" wrap="nowrap">
                      <Group style={{ flex: 1 }} justify="space-between" wrap="nowrap">
                        <Group gap={40} wrap="nowrap">
                          {/* MAIA: Maia wordmark links to /query */}
                          <Link to="/query" style={{ textDecoration: "none", color: "white" }}>
                            <Text fz={22} fw={700} style={{ letterSpacing: 1 }}>
                              Maia
                            </Text>
                          </Link>
                        </Group>
                        <Group visibleFrom="xs" wrap="nowrap" gap="xs">
                          {/* MAIA: project switcher + Classic UI link */}
                          <MaiaProjectSwitcher />
                          {navActionIcons}
                        </Group>
                      </Group>
                      <Burger
                        opened={opened}
                        onClick={toggle}
                        hiddenFrom="sm"
                        size="sm"
                        color="gray.2"
                      />
                    </Group>
                  </AppShell.Header>

                  <AppShell.Navbar py="md" px={4} bg="rgb(65, 73, 81)" c="#fff">
                    <Group mt="md" hiddenFrom="xs" justify="center">
                      {navActionIcons}
                    </Group>
                  </AppShell.Navbar>

                  <AppShell.Main>
                    <ErrorBoundary key={location.pathname}>
                      <Suspense
                        fallback={
                          <Box mt="lg">
                            {Array.from(Array(10), (_, i) => (
                              <Skeleton key={i} height={40} mb={15} width={1000} mx="auto" />
                            ))}
                          </Box>
                        }
                      >
                        <Routes>
                          <Route
                            path="/"
                            element={<Navigate to={agentMode ? "/agent" : "/query"} replace />}
                          />
                          {agentMode ? (
                            <Route path="/agent" element={<ReadinessWrapper><AgentPage /></ReadinessWrapper>} />
                          ) : (
                            <Route path="/query" element={<ReadinessWrapper><QueryPage /></ReadinessWrapper>} />
                          )}
                          {/* MAIA: redirect all Prometheus-only paths to /query */}
                          <Route path="/alerts" element={<Navigate to="/query" replace />} />
                          <Route path="/rules" element={<Navigate to="/query" replace />} />
                          <Route path="/targets" element={<Navigate to="/query" replace />} />
                          <Route path="/service-discovery" element={<Navigate to="/query" replace />} />
                          <Route path="/status" element={<Navigate to="/query" replace />} />
                          <Route path="/tsdb-status" element={<Navigate to="/query" replace />} />
                          <Route path="/flags" element={<Navigate to="/query" replace />} />
                          <Route path="/config" element={<Navigate to="/query" replace />} />
                          <Route path="/alertmanager-discovery" element={<Navigate to="/query" replace />} />
                        </Routes>
                      </Suspense>
                    </ErrorBoundary>
                  </AppShell.Main>
                </AppShell>
              </MaiaProjectProvider>
            </QueryClientProvider>
          </CodeHighlightAdapterProvider>
        </MantineProvider>
      </QueryParamProvider>
    </BrowserRouter>
  );
}

export default App;
