import axios, { AxiosRequestConfig } from "axios";
import { BaseAuthService } from "./auth/base-auth-service";

export class TimeOffService extends BaseAuthService {

    constructor() {
        super();
    }

    getTimeOffsByUserAndMonths(data: any, config: AxiosRequestConfig<any> | undefined, 
            then: (response: any) => void, 
            onCatch: (error:any) => void) {
                
                axios.post("http://localhost:5122/timeOff/get-time-offs-by-user-and-months", 
                    data, config).then(then).catch(onCatch);
    }

}