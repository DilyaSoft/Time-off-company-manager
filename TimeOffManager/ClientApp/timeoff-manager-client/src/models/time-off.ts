import { Manager } from "./manager";
import { User } from "./user";

export interface TimeOff {
    id:number;
    type:TimeOffType;
    approvedDate:Date;
    startDate:Date;
    endDate:Date;
    isApproved:boolean;
    note?:string;
    managerId?: number;
    manager?:Manager;
    employeeId: number;
    employee:User;
    approverId?:number;
    approveManager?:Manager;
}

export enum TimeOffType {
    Vacation = 1,
    SickLeave = 2
}