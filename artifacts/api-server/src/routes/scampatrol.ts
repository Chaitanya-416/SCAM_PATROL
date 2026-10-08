import { Router, type IRouter } from "express";
import {
  CreateScanBody,
  CreateScanResponse,
  GetDashboardResponse,
  GetIncidentParams,
  GetIncidentResponse,
  GetIncidentsQueryParams,
  GetIncidentsResponse,
  GetReputationQueryParams,
  GetReputationResponse,
  ReportIncidentBody,
  ReportIncidentParams,
  ReportIncidentResponse,
} from "@workspace/api-zod";
import {
  getDashboardData,
  getIncident,
  listIncidents,
  listReputation,
  reportIncident,
} from "../lib/scampatrol-db";
import { analyzeScan, seedDemoIncidents } from "../lib/scampatrol-engine";

const router: IRouter = Router();

seedDemoIncidents();

router.post("/scans", (req, res): void => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  if (!parsed.data.input.trim()) {
    res.status(400).json({ error: "Enter something to analyze." });
    return;
  }
  const result = analyzeScan({
    ...parsed.data,
    input: parsed.data.input.trim(),
    callerName: parsed.data.callerName?.trim(),
  });
  res.status(201).json(CreateScanResponse.parse(result));
});

router.get("/dashboard", (_req, res): void => {
  res.json(GetDashboardResponse.parse(getDashboardData()));
});

router.get("/incidents", (req, res): void => {
  const parsed = GetIncidentsQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const result = listIncidents({
    search: parsed.data.search,
    kind: parsed.data.kind,
    minRisk: parsed.data.minRisk,
    limit: parsed.data.limit ?? 50,
    offset: parsed.data.offset ?? 0,
  });
  res.json(GetIncidentsResponse.parse(result));
});

router.get("/incidents/:id", (req, res): void => {
  const params = GetIncidentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const incident = getIncident(params.data.id);
  if (!incident) {
    res.status(404).json({ error: "Incident not found." });
    return;
  }
  res.json(GetIncidentResponse.parse(incident));
});

router.post("/incidents/:id/report", (req, res): void => {
  const params = ReportIncidentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const body = ReportIncidentBody.safeParse(req.body ?? {});
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }
  const reputation = reportIncident(params.data.id, body.data.reason?.trim());
  if (!reputation) {
    res.status(404).json({ error: "Incident not found." });
    return;
  }
  res.json(ReportIncidentResponse.parse(reputation));
});

router.get("/reputation", (req, res): void => {
  const parsed = GetReputationQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  res.json(
    GetReputationResponse.parse(
      listReputation(parsed.data.search, parsed.data.limit ?? 50),
    ),
  );
});

export default router;
