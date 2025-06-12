import { Router } from 'express';
import { validateJoi } from '../../middlewares/joiValidationMiddleware';
import requireAuth from '../../middlewares/authMiddleware';
import permit from '../../middlewares/permissionMiddleware';
import { RoleType } from '../../utils/enums';
import { userController } from '../../controllers';
import {
    userUpdateRequestSchema,
    getUserByIdRequestSchema,
    getAllUsersRequestSchema
} from '../../schemas/userSchemas';
import { protectedRouteSchema } from '../../schemas/authSchemas';

//USER ROUTES//
const _router: Router = Router({
    mergeParams: true,
});

//UPDATE USER DETAILS
_router.route('/update/:userId').patch(
    validateJoi({
        ...userUpdateRequestSchema,
        headers: protectedRouteSchema.headers
    }),
    requireAuth,
    permit([RoleType.ADMIN, RoleType.USER]),
    userController.updateUser
);

//GET USER DETAILS BY ID
_router
    .route('/fetch/:userId')
    .get(
        validateJoi({
            ...getUserByIdRequestSchema,
            headers: protectedRouteSchema.headers
        }),
        requireAuth,
        permit([RoleType.ADMIN, RoleType.USER]),
        userController.getUser
    );

//GET ALL USER LIST
_router
    .route('/fetch')
    .get(
        validateJoi({
            ...getAllUsersRequestSchema,
            headers: protectedRouteSchema.headers
        }),
        requireAuth,
        permit([RoleType.ADMIN, RoleType.USER]),
        userController.getAllUser
    );

//EXPORT
export const router = _router;
