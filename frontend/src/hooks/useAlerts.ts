import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { alertsApi } from "../api/client";
import type { AlertFilters } from "../types";

export const useAlerts = (filters: AlertFilters = {}) =>
  useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => alertsApi.list(filters),
    refetchInterval: 30000,
    keepPreviousData: true,
  });

export const useAlert = (id: number | null) =>
  useQuery({
    queryKey: ["alert", id],
    queryFn: () => alertsApi.get(id!),
    enabled: id !== null,
  });

export const useAlertEvents = (id: number | null) =>
  useQuery({
    queryKey: ["alert-events", id],
    queryFn: () => alertsApi.getEvents(id!),
    enabled: id !== null,
  });

export const useUpdateAlertStatus = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      alertsApi.updateStatus(id, status),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["stats"] });
    },
  });
};
