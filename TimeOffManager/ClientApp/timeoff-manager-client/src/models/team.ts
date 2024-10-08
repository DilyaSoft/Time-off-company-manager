import { Company } from "./company";
import { User } from "./user";

export interface Team {
    id:number;
    name:string;
    companyId:number;
    company:Company;
    users: User[];
}