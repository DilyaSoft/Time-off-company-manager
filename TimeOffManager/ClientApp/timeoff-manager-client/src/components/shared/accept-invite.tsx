import { Alert, AlertTitle, Button, Dialog, DialogActions, DialogTitle, InputLabel, TextField } from "@mui/material";
import { DatePicker, LocalizationProvider } from "@mui/x-date-pickers";
import { useState } from "react";
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import dayjs, { Dayjs } from 'dayjs';
import axios, { AxiosResponse } from "axios";
import { useNavigate } from "react-router-dom";
import { SignInResult } from "../../models/sign-in-result";
import { ApplciationSettings } from "../../models/application-settings";


function AcceptInvitePage() {
    const [showErrors, setShowErrors] = useState(false);
    const navigateTo = useNavigate();
    const [validationErrors, setValidationErrors] = useState([""]);
    const [showEditAccount, setShowEditAccount] = useState(false);
    
    function ValidationErrors() {
        if (!showErrors) {
            return (<></>);
          }
      
          let errors = [];
          for (let i = 0; i < validationErrors.length; i++) {
            errors.push(<p key={i}>{validationErrors[i] + " \r\n"}</p>);
          }
          return (<Alert className='alert-validation-dialog' severity="error">
            <AlertTitle>Error</AlertTitle>
             {errors}
          </Alert>);
    }

    function EditAccountDialog() {

        const handleCloseAccountEdit = () => {
            setShowEditAccount(false);
        };

        let url = window.location.href;

        let paramsUrl = url.split("?");
        if (paramsUrl.length == 1) {
            navigateTo("/");
        }
        let paramsPart = paramsUrl[1];
        let paramsArray = paramsPart.split("&");
        let email = "";
        let token = "";
        let fName= "";
        let lName = "";

        for (let i =0; i < paramsArray.length; i++) {
            if (paramsArray[i].includes("email")) {
                let split = paramsArray[i].split("=");
                email = split[1];
                if (!email) {
                    navigateTo("/");
                }
            }
            if (paramsArray[i].includes("token")) {
                let split = paramsArray[i].split("=");
                token = split[1];
                if (!token) {
                    navigateTo("/");
                }
            }
            if (paramsArray[i].includes("fName")) {
                let split = paramsArray[i].split("=");
                fName = split[1];
            }
            if (paramsArray[i].includes("lName")) {
                let split = paramsArray[i].split("=");
                lName = split[1];
            }
        }

        axios.get(`${ApplciationSettings.webApiUrl()}/account/is-invite-valid?emeil=${email}`)
            .then((res:AxiosResponse<boolean>) => {
                if (!res.data) {
                    navigateTo("/");
                } else {
                    setShowEditAccount(true);
                }
            });

        const updateAccountClick = () => {
            for (let i =0; i < paramsArray.length; i++) {
                if (paramsArray[i].includes("email")) {
                    let split = paramsArray[i].split("=");
                    email = split[1];
                }
                if (paramsArray[i].includes("token")) {
                    token = "";
                    let split = paramsArray[i].split("=");
                    if (split.length > 2) {
                        for (let i = 1; i < split.length; i++) {
                            token += split[i] == "" ? "=" : split[i];
                        }
                    }
                }
                if (paramsArray[i].includes("fName")) {
                    let split = paramsArray[i].split("=");
                    fName = split[1];
                }
                if (paramsArray[i].includes("lName")) {
                    let split = paramsArray[i].split("=");
                    lName = split[1];
                }
            }
            setShowErrors(false);
            setValidationErrors([]);
            let errors = [];

            let password = document.getElementById("new-password") as HTMLInputElement;

            if (!password.value) {
                errors.push("Password is requried");
                setShowErrors(true);
                setValidationErrors(errors);
                return;
            }

            let bDate = document.getElementById("BirthDate") as HTMLInputElement;
            let title = document.getElementById("job-title") as HTMLInputElement;

            axios.post(`${ApplciationSettings.webApiUrl()}/account/accept-invite`, {
                resetToken: token,
                email:email,
                newPassword: password.value,
                BirthDate: new Date(bDate.value),
                jobTitle: title.value
            }, {})
            .then((res:AxiosResponse<SignInResult>) => {
                if (!res.data.success) {
                    setShowErrors(true);
                    validationErrors.push(res.data.message);
                    setValidationErrors(validationErrors);
                  } else {
                    localStorage.setItem("ACCESS_TOKEN", res.data.token.accessToken);
                    localStorage.setItem("REFRESH_ACCESS_TOKEN", res.data.token.refreshToken);
                    navigateTo("/workspace");
                  }
            });
        };

        return (<>
        
            <Dialog
                open={showEditAccount}
                onClose={handleCloseAccountEdit}
                aria-labelledby="responsive-dialog-title">
                    <DialogTitle id="responsive-dialog-title">
                        <span style={{ padding: "20px" }} className='flex-column'>
                            <ValidationErrors/>
                            <span className='bold'>Edit Account <AccountCircleIcon/></span> 
                        </span>
                    </DialogTitle>
                    <form className='flex-column' style={{ margin: "0px 40px 40px 40px" }}>
                            <TextField
                                required
                                autoComplete='first-name'
                                id="first-name"
                                margin="normal"
                                label="First Name"
                                defaultValue={fName}
                                variant="standard"
                            />
                            <TextField
                                required
                                autoComplete='last-name'
                                id="last-name"
                                margin="normal"
                                label="Last Name"
                                defaultValue={lName}
                                variant="standard"
                            />
                            <TextField
                                required
                                disabled
                                autoComplete='email'
                                id="email"
                                margin="normal"
                                label="Email"
                                defaultValue={email}
                                variant="standard"
                            />
                              <TextField
                                required
                                type={"password"}
                                autoComplete='password'
                                id="new-password"
                                margin="normal"
                                label="New password"
                                defaultValue={""}
                                variant="standard"
                            />
                            <TextField
                                autoComplete='job'
                                id="job-title"
                                margin="normal"
                                label="Job Title"
                                defaultValue={""}
                                variant="standard"
                            />
                            <TextField
                                disabled
                                autoComplete='start-date'
                                id="startdate"
                                margin="normal"
                                label="Employment start date"
                                defaultValue={new Date().toDateString()}
                                variant="standard"
                            />
                            <InputLabel style={{ color: "black"}} id="team-select-label">Birthdate </InputLabel>
                            <LocalizationProvider dateAdapter={AdapterDayjs}>
                                <DatePicker  slotProps={{
                                textField: {
                                    required: true,
                                    id: 'BirthDate',
                                },
                                }} value={dayjs(new Date())} />
                            </LocalizationProvider>
                    </form>
                    <DialogActions className='flex-row-center'>
                        <Button autoFocus onClick={updateAccountClick}>
                            <span>Save</span>
                        </Button>
                    </DialogActions>
                </Dialog>
        
        </>);
    }

    return (<>

        <EditAccountDialog/>
        
    </>);
}

export default AcceptInvitePage;