import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import { ApplciationSettings } from '../../models/application-settings';
import { Token } from '../../models/sign-in-result';

export class AuthService  {

    constructor() {
        axios.interceptors.request.use(
            (config) => {
                let token = localStorage.getItem("ACCESS_TOKEN") || "";
                config.headers["Authorization"] = 'Bearer ' + token;
                config.headers["Access-Control-Allow-Origin"] = "*";
                return config;
            },
            (error) => {
                console.log(error);
            }
        );
        axios.interceptors.response.use(
            (config) => {
                return config;
            },
            (error) => {
                if (error.response.status == 401) {
                    axios.post(`${ApplciationSettings.webApiUrl()}/account/refresh-token`, { 
                    }).
                    then(function (token:AxiosResponse<Token>) {
                            if (!token?.data) {
                                console.error("token wasn't refreshed");
                            } else {
                                localStorage.setItem("ACCESS_TOKEN", token?.data.accessToken);
                                localStorage.setItem("REFRESH_ACCESS_TOKEN", token?.data.refreshToken);
                            }
        
                        })
                        .catch(function (error) {
                            console.log(error);
                        });
                }
                console.log(error);
            }
        );
    }

    getUserIfAuthorized(config:AxiosRequestConfig<any> | undefined, 
        then: (response: any) => void, 
        onCatch: (error:any) => void ) {
         return axios.get(`${ApplciationSettings.webApiUrl()}/account/get-authorized?withCompany=true`, config).then(then)
            .catch(onCatch);
    }

    post(url: string, data: any, config:AxiosRequestConfig<any> | undefined, 
        then: (response: any) => void, 
        onCatch: (error:any) => void) {
        axios.post(url, data, config).then(then).catch(onCatch);
    }

}