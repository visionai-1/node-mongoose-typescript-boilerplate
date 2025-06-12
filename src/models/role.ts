import mongoose, { Document, Schema } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { IRole } from '../interfaces';

export interface IRoleModel extends IRole, Document {
  _id: string;
}

const RoleSchema: Schema<IRoleModel> = new Schema(
  {
    _id: {
      type: String,
      default: uuidv4,
    },
    name: {
      type: String,
      required: [true, 'role is required'],
    },
  },
  { timestamps: true }
);

export default mongoose.model<IRoleModel>('Role', RoleSchema);
