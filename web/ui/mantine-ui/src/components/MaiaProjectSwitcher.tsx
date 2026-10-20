// MAIA: project switcher navbar component — shows current project dropdown
// and logged-in username. Maia-specific — do not overwrite during upstream syncs.
import { Group, Loader, Select, Text } from "@mantine/core";
import { useMaiaProject } from "../context/useMaiaProject";

export function MaiaProjectSwitcher() {
  const { user, projects, currentProject, isLoading, setProject } = useMaiaProject();

  // Show a small spinner while the initial whoami/projects fetch is in flight.
  if (isLoading) {
    return <Loader size="xs" color="gray" />;
  }

  if (!currentProject) return null;

  const options = projects.map((p) => ({ value: p.id, label: p.name }));

  return (
    <Group gap="xs" wrap="nowrap">
      {user && (
        <Text size="sm" c="gray.3" style={{ whiteSpace: "nowrap" }}>
          {user.userName}
        </Text>
      )}
      <Select
        size="xs"
        data={options}
        value={currentProject.id}
        onChange={(id) => {
          const p = projects.find((p) => p.id === id);
          if (p) setProject(p);
        }}
        styles={{ input: { minWidth: 140 } }}
        allowDeselect={false}
      />
      {/* MAIA: Classic UI link moved to top banner — see App.tsx */}
    </Group>
  );
}
