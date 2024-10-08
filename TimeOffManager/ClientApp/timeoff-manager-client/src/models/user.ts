import { Team } from "./team";

export interface User {
    id:number;
    firstName:string;
    lastName:string;
    email:string;
    teamId:number;
    team:Team | null;
    totalAllowanceTimeOffInYear: number;
    tookAllowanceTimeOff: number;
    birthDate: Date;
    startWorkDate: Date;
    roleName: string;
    inviteStatus: InviteStatus;
}


export enum InviteStatus {
    None = 0,
    WaitForAccept = 1,
    Accepted = 2
}