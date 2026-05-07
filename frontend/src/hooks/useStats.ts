import { useQuery } from "@tanstack/react-query";
import { statsApi } from "../api/client";

export const useSummary = () =>
  useQuery({ queryKey: ["stats", "summary"], queryFn: statsApi.summary, refetchInterval: 30000 });

export const useTimeline = (hours = 24, bucket_minutes = 60) =>
  useQuery({
    queryKey: ["stats", "timeline", hours, bucket_minutes],
    queryFn: () => statsApi.timeline(hours, bucket_minutes),
    refetchInterval: 60000,
  });

export const useTopSources = (hours = 24) =>
  useQuery({
    queryKey: ["stats", "top-sources", hours],
    queryFn: () => statsApi.topSources(hours, 10),
    refetchInterval: 60000,
  });

export const useEventTypes = (hours = 24) =>
  useQuery({
    queryKey: ["stats", "event-types", hours],
    queryFn: () => statsApi.eventTypes(hours),
    refetchInterval: 60000,
  });

export const useMitreCoverage = () =>
  useQuery({
    queryKey: ["stats", "mitre-coverage"],
    queryFn: () => statsApi.mitreCoverage(168),
    refetchInterval: 120000,
  });

export const useInvestigateIp = (ip: string | null) =>
  useQuery({
    queryKey: ["investigation", "ip", ip],
    queryFn: () => statsApi.investigateIp(ip!),
    enabled: !!ip,
  });

export const useInvestigateUser = (username: string | null) =>
  useQuery({
    queryKey: ["investigation", "user", username],
    queryFn: () => statsApi.investigateUser(username!),
    enabled: !!username,
  });
