import axios, { AxiosRequestConfig } from "axios";
import { ApplciationSettings } from "../../models/application-settings";
import { BaseAuthService } from "./base-auth-service";

export class CompanyService extends BaseAuthService {

    getCompanyUsers(config:AxiosRequestConfig<any> | undefined, 
        then: (response: any) => void, 
        onCatch: (error:any) => void, companyId: number | undefined) 
    {
        return axios.get(`${ApplciationSettings.webApiUrl()}/company/get-company-users?companyId=${companyId}`
            ,config).then(then)
            .catch(onCatch);
    }
}