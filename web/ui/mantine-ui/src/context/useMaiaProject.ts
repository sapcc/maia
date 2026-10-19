// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

// MAIA: project context object and hook, kept apart from MaiaProjectProvider
// so that file only exports a component (keeps React Fast Refresh working).
// This file is Maia-specific — do not overwrite during upstream syncs.
import { createContext, useContext } from "react";

export interface MaiaUser {
  userId: string;
  userName: string;
  userDomainName: string;
  projectId: string;
  projectName: string;
  domainId: string;
  domainName: string;
  roles: string[];
}

export interface MaiaProject {
  id: string;
  name: string;
}

export interface MaiaProjectContextValue {
  user: MaiaUser | null;
  projects: MaiaProject[];
  currentProject: MaiaProject | null;
  // isLoading is true during the initial whoami/projects fetch.
  // Consumers can use this to show a skeleton instead of empty state.
  isLoading: boolean;
  setProject: (project: MaiaProject) => void;
}

export const MaiaProjectContext = createContext<MaiaProjectContextValue>({
  user: null,
  projects: [],
  currentProject: null,
  isLoading: true,
  setProject: () => undefined,
});

export const useMaiaProject = (): MaiaProjectContextValue =>
  useContext(MaiaProjectContext);
