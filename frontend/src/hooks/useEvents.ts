import { useQuery } from "@tanstack/react-query";
import { eventsApi } from "../api/client";
import type { EventFilters } from "../types";

export const useEvents = (filters: EventFilters = {}) =>
  useQuery({
    queryKey: ["events", filters],
    queryFn: () => eventsApi.list(filters),
    keepPreviousData: true,
  });

export const useEvent = (id: number | null) =>
  useQuery({
    queryKey: ["event", id],
    queryFn: () => eventsApi.get(id!),
    enabled: id !== null,
  });
