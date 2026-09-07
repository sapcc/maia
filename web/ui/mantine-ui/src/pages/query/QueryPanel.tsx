import {
  Group,
  Tabs,
  Center,
  Space,
  Box,
  SegmentedControl,
  Stack,
  ActionIcon,
  Popover,
  Checkbox,
} from "@mantine/core";
import {
  IconAdjustmentsHorizontal,
  IconChartAreaFilled,
  IconChartLine,
  IconGraph,
  IconTable,
} from "@tabler/icons-react";
import { FC, useCallback, useState } from "react";
import { useAppDispatch, useAppSelector } from "../../state/hooks";
import {
  addQueryToHistory,
  duplicatePanel,
  GraphDisplayMode,
  GraphResolution,
  removePanel,
  setExpr,
  setVisualizer,
} from "../../state/queryPageSlice";
import TimeInput from "./TimeInput";
import RangeInput from "./RangeInput";
import ExpressionInput from "./ExpressionInput";
import Graph from "./Graph";
import ResolutionInput from "./ResolutionInput";
import TableTab from "./TableTab";
// MAIA: TreeView removed — requires /api/v1/parse_query which is not available on Thanos
import { actionIconStyle } from "../../styles";

export interface PanelProps {
  idx: number;
  metricNames: string[];
}

// TODO: This is duplicated everywhere, unify it.
const iconStyle = { width: "0.9rem", height: "0.9rem" };

const QueryPanel: FC<PanelProps> = ({ idx, metricNames }) => {
  // Used to indicate to the selected display component that it should retrigger
  // the query, even if the expression has not changed (e.g. when the user presses
  // the "Execute" button or hits <Enter> again).
  const [retriggerIdx, setRetriggerIdx] = useState<number>(0);

  const panel = useAppSelector((state) => state.queryPage.panels[idx]);
  const dispatch = useAppDispatch();

  const expr = panel.expr;

  const onSelectRange = useCallback(
    (start: number, end: number) =>
      dispatch(
        setVisualizer({
          idx,
          visualizer: {
            ...panel.visualizer,
            range: (end - start) * 1000,
            endTime: end * 1000,
          },
        })
      ),
    // TODO: How to have panel.visualizer in the dependencies, but not re-create
    // the callback every time it changes by the callback's own update? This leads
    // to extra renders of the plot further down.
    [dispatch, idx, panel.visualizer]
  );

  return (
    <Stack gap="lg">
      <ExpressionInput
        // TODO: Maybe just pass the panelIdx and retriggerIdx to the ExpressionInput
        // so it can manage its own state?
        initialExpr={panel.expr}
        metricNames={metricNames}
        executeQuery={(expr: string) => {
          setRetriggerIdx((idx) => idx + 1);
          dispatch(setExpr({ idx, expr }));

          if (!metricNames.includes(expr) && expr.trim() !== "") {
            dispatch(addQueryToHistory(expr));
          }
        }}
        duplicatePanel={(expr: string) => {
          dispatch(duplicatePanel({ idx, expr }));
        }}
        removePanel={() => {
          dispatch(removePanel(idx));
        }}
      />
      <Tabs
        value={panel.visualizer.activeTab}
        onChange={(v) =>
          dispatch(
            setVisualizer({
              idx,
              visualizer: {
                ...panel.visualizer,
                activeTab: v as "table" | "graph",
              },
            })
          )
        }
        keepMounted={false}
      >
        <Tabs.List>
          <Tabs.Tab value="table" leftSection={<IconTable style={iconStyle} />}>
            Table
          </Tabs.Tab>
          <Tabs.Tab value="graph" leftSection={<IconGraph style={iconStyle} />}>
            Graph
          </Tabs.Tab>
          {/* MAIA: Explain tab disabled — requires /api/v1/parse_query which
              is not available on Thanos query frontends */}
        </Tabs.List>
        <Tabs.Panel pt="sm" value="table">
          <TableTab expr={expr} panelIdx={idx} retriggerIdx={retriggerIdx} />
        </Tabs.Panel>
        <Tabs.Panel pt="sm" value="graph">
          <Group mt="xs" justify="space-between">
            <Group>
              <RangeInput
                range={panel.visualizer.range}
                onChangeRange={(range) =>
                  dispatch(
                    setVisualizer({
                      idx,
                      visualizer: { ...panel.visualizer, range },
                    })
                  )
                }
              />
              <TimeInput
                time={panel.visualizer.endTime}
                range={panel.visualizer.range}
                description="End time"
                onChangeTime={(time) =>
                  dispatch(
                    setVisualizer({
                      idx,
                      visualizer: { ...panel.visualizer, endTime: time },
                    })
                  )
                }
              />
              <ResolutionInput
                resolution={panel.visualizer.resolution}
                range={panel.visualizer.range}
                onChangeResolution={(res: GraphResolution) => {
                  dispatch(
                    setVisualizer({
                      idx,
                      visualizer: {
                        ...panel.visualizer,
                        resolution: res,
                      },
                    })
                  );
                }}
              />
            </Group>

            <Group gap="lg">
              {/* <Button
                variant="subtle"
                color="gray.9"
                size="xs"
                leftSection={
                  panel.visualizer.showExemplars ? (
                    <IconCheckbox
                      style={{
                        width: "1.5em",
                        height: "1.5em",
                        marginRight: -1,
                      }}
                    />
                  ) : (
                    <IconSquare
                      style={{
                        width: "1.3em",
                        height: "1.3em",
                      }}
                    />
                  )
                }
                onClick={() =>
                  dispatch(
                    setVisualizer({
                      idx,
                      visualizer: {
                        ...panel.visualizer,
                        showExemplars: !panel.visualizer.showExemplars,
                      },
                    })
                  )
                }
              >
                Show exemplars
              </Button> */}

              <SegmentedControl
                onChange={(value) =>
                  dispatch(
                    setVisualizer({
                      idx,
                      visualizer: {
                        ...panel.visualizer,
                        displayMode: value as GraphDisplayMode,
                      },
                    })
                  )
                }
                value={panel.visualizer.displayMode}
                data={[
                  {
                    value: GraphDisplayMode.Lines,
                    label: (
                      <Center>
                        <IconChartLine style={iconStyle} />
                        <Box ml={10}>Unstacked</Box>
                      </Center>
                    ),
                  },
                  {
                    value: GraphDisplayMode.Stacked,
                    label: (
                      <Center>
                        <IconChartAreaFilled style={iconStyle} />
                        <Box ml={10}>Stacked</Box>
                      </Center>
                    ),
                  },
                  // {
                  //   value: GraphDisplayMode.Heatmap,
                  //   label: (
                  //     <Center>
                  //       <IconChartGridDots style={iconStyle} />
                  //       <Box ml={10}>Heatmap</Box>
                  //     </Center>
                  //   ),
                  // },
                ]}
              />
              <Popover position="bottom" withArrow shadow="md">
                <Popover.Target>
                  <ActionIcon
                    variant="light"
                    color="gray"
                    size={32}
                    title="Graph settings"
                  >
                    <IconAdjustmentsHorizontal
                      style={actionIconStyle}
                      stroke={1.5}
                    />
                  </ActionIcon>
                </Popover.Target>
                <Popover.Dropdown p="lg">
                  <Checkbox
                    size="xs"
                    checked={panel.visualizer.yAxisMin !== null}
                    label="Start Y axis at 0"
                    onChange={(event) =>
                      dispatch(
                        setVisualizer({
                          idx,
                          visualizer: {
                            ...panel.visualizer,
                            yAxisMin: event.currentTarget.checked ? 0 : null,
                          },
                        })
                      )
                    }
                  />
                </Popover.Dropdown>
              </Popover>
            </Group>
          </Group>
          <Space h="lg" />
          <Graph
            expr={expr}
            node={null}
            endTime={panel.visualizer.endTime}
            range={panel.visualizer.range}
            resolution={panel.visualizer.resolution}
            showExemplars={panel.visualizer.showExemplars}
            displayMode={panel.visualizer.displayMode}
            yAxisMin={panel.visualizer.yAxisMin}
            retriggerIdx={retriggerIdx}
            onSelectRange={onSelectRange}
          />
        </Tabs.Panel>
        {/* MAIA: Explain tab panel removed — parse_query not available on Thanos */}
      </Tabs>
    </Stack>
  );
};

export default QueryPanel;
