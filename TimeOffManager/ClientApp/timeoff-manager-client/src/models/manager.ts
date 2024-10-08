import { Team } from "./team";

export interface Manager {
    id:number;
    firstName:string;
    lastName:string;
    email:string;
    teamId:number;
    team:Team | null;
}