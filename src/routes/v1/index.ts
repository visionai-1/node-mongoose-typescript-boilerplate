import { NextFunction, Request, Response, Router } from 'express';
import { router as Role } from './role.route';
import { router as UserRouter } from './user.route';
import { router as LoginRouter } from './login.route';
import { validateJoi } from '../../middlewares/joiValidationMiddleware';
import { protectedRouteSchema } from '../../schemas/authSchemas';
import requireAuth from '../../middlewares/authMiddleware';

const _router: Router = Router({
    mergeParams: true,
});

//DEFINE API VERSION
_router.use(function (req: Request, res: Response, next: NextFunction) {
    res.setHeader('Api-Version', 'v1');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    next();
});

// HEALTHCHECK
_router.route('/v1/health-check').get(function (req: Request, res: Response) {
    return res.status(200).json({ healthy: true, version: 'v1' });
});

// EXAMPLE: Protected route using unified auth middleware with Joi validation
_router.route('/v1/me').get(
    validateJoi(protectedRouteSchema),
    requireAuth,
    function (req: Request, res: Response) {
        return res.status(200).json({
            message: 'User authenticated successfully',
            userId: req.userId,
            sessionId: req.sessionId || null,
            tokenPayload: req.tokenPayload,
            hasSession: !!req.sessionData,
            sessionInfo: req.sessionData ? {
                userId: req.sessionData.userId,
                isActive: req.sessionData.isActive,
                lastActivity: req.sessionData.lastActivity,
                browserInfo: req.sessionData.browserInfo || null,
                sessionType: req.sessionData.type
            } : null
        });
    }
);

//EXPORT ROUTES WITH BASEPATH
_router.use('/v1/role', Role);
_router.use('/v1/user', UserRouter);
_router.use('/v1/auth', LoginRouter);

export const router = _router;
