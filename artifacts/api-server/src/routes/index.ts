import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scamPatrolRouter from "./scampatrol";

const router: IRouter = Router();

router.use(healthRouter);
router.use(scamPatrolRouter);

export default router;
