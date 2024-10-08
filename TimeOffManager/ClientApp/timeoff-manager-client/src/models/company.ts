import { Team } from "./team";

export interface Company {
    id:number;
    name:string;
    logo:[];
    logoBase64:string;
    teams:Team[];
}