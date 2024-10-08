import { Alert, AlertTitle, Button, Dialog, DialogActions, DialogTitle, IconButton, InputLabel, Menu, MenuItem, TextField } from "@mui/material"
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { User } from "../../models/user";
import { useState, createContext, useContext, useCallback } from "react";
import { AuthService } from "../../services/auth/auth-service";
import { useNavigate } from "react-router-dom";
import ApartmentIcon from '@mui/icons-material/Apartment';
import axios, { AxiosResponse } from "axios";
import { Company } from "../../models/company";
import { DatePicker, LocalizationProvider } from "@mui/x-date-pickers";
import dayjs, { Dayjs } from 'dayjs';
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import { ApplciationSettings } from "../../models/application-settings";

function UserProfileInfoDialog({currentUser}: { currentUser: User}) {

    const [showMenuProfileOpen, setShowMenuProfileOpen] = useState(false);
    const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
    const [showEditCompanyDialog, setShowEditCompanyDialog] = useState(false);
    const [showEditProfile, setShowEditProfileDialog] = useState(false);
    const navigateTo = useNavigate();
    const [showErrors, setShowErrors] = useState(false);
    const [validationErrors, setValidationErrors] = useState([""]);
    
    const maxLogoByteSize = 2000000;

    function ProfileDialog() {
        const needToUpdate = () => {
            const fName = document.getElementById("first-name") as HTMLInputElement;
            const lName = document.getElementById("last-name") as HTMLInputElement;
            const email = document.getElementById("email") as HTMLInputElement;
            const bDate = document.getElementById("BirthDate") as HTMLInputElement;
            const uDate = new Date(currentUser.birthDate).toISOString();

            return currentUser.firstName != fName.value || currentUser.lastName != lName.value
             || currentUser.email != email.value || uDate != bDate.value;
        };

        const updateProfileClick = () => {

            if (needToUpdate()) {

                const fName = document.getElementById("first-name") as HTMLInputElement;
                const lName = document.getElementById("last-name") as HTMLInputElement;
                const email = document.getElementById("email") as HTMLInputElement;
                const bDate = document.getElementById("BirthDate") as HTMLInputElement;

                let errors = [];
                setValidationErrors([""]);
                setShowErrors(false);

                if (!fName.value) {
                    errors.push("First name is requried");
                    setValidationErrors(errors);
                }

                if (!lName.value) {
                    errors.push("Last name is requried");
                    setValidationErrors(errors);
                }

                if (!email.value) {
                    errors.push("Email is requried");
                    setValidationErrors(errors);
                }

                if (!bDate.value) {
                    errors.push("Birthdate is requried");
                    setValidationErrors(errors);
                }

                if (errors.filter(x => x != "").length > 0) {
                    setShowErrors(true);
                    return;
                }

                axios.post(`${ApplciationSettings.webApiUrl()}/account/update-profile`, {
                    firstName: fName.value,
                    lastName: lName.value,
                    email: email.value,
                    
                    birthDate: new Date(bDate.value)
                }).then(() => {
                    currentUser.firstName = fName.value;
                    currentUser.lastName = lName.value;
                    currentUser.email = email.value;
                    currentUser.birthDate = dayjs(new Date(bDate.value));
                    // setCurrentUser(currentUser);
                    setShowEditProfileDialog(false);
                }).catch((err) => console.error(err));
            } else {
                setShowEditProfileDialog(false);
            }
        };

        const handleCloseProfileEdit = () => {
            setShowEditProfileDialog(false);
            setShowErrors(false);
            setValidationErrors([]);
        };

        return (<>
            <Dialog
                open={showEditProfile}
                onClose={handleCloseProfileEdit}
                aria-labelledby="responsive-dialog-title">
                <DialogTitle id="responsive-dialog-title">
                    <span style={{ padding: "20px" }} className='flex-column'>
                        <ValidationErrors/>
                        <span className='bold'>Profile Info <AccountCircleIcon/></span> 
                    </span>
                </DialogTitle>
                <form className='flex-column' style={{ margin: "0px 40px 40px 40px" }}>
                        <TextField
                            required
                            autoComplete='first-name'
                            id="first-name"
                            margin="normal"
                            label="First Name"
                            defaultValue={currentUser.firstName}
                            variant="standard"
                        />
                        <TextField
                            required
                            autoComplete='last-name'
                            id="last-name"
                            margin="normal"
                            label="Last Name"
                            defaultValue={currentUser.lastName}
                            variant="standard"
                        />
                         <TextField
                            required
                            autoComplete='email'
                            id="email"
                            margin="normal"
                            label="Email"
                            defaultValue={currentUser.email}
                            variant="standard"
                        />
                         <TextField
                            disabled
                            autoComplete='start-date'
                            id="startdate"
                            margin="normal"
                            label="Employment start date"
                            defaultValue={new Date(currentUser.startWorkDate)?.toDateString()}
                            variant="standard"
                        />
                          <InputLabel style={{ color: "black"}} id="team-select-label">Birthdate </InputLabel>
                          <LocalizationProvider dateAdapter={AdapterDayjs}>
                            <DatePicker  slotProps={{
                             textField: {
                                required: true,
                                id: 'BirthDate',
                            },
                            }} value={dayjs(currentUser.birthDate)} />
                          </LocalizationProvider>
                          <p>Total days to request time off: {currentUser.totalAllowanceTimeOffInYear - currentUser.tookAllowanceTimeOff}</p>
                </form>
                <DialogActions className='flex-row-center'>
                    <Button autoFocus onClick={updateProfileClick}>
                        <span>Save</span>
                    </Button>
                    <Button autoFocus onClick={handleCloseProfileEdit}>
                        <span>Cancel</span>
                    </Button>
                </DialogActions>
            </Dialog>
        </>);
    }


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

    function EditCompanyDialog() {

        const handleCloseLogin = () => {
            setShowEditCompanyDialog(false);
            setValidationErrors([""]);
            setShowErrors(false);
        };

        const handleSaveCompanyEdit = () => {
            let errors = [];
            let authService = new AuthService();
            setValidationErrors([""]);
            setShowErrors(false);
            const companyName = document.getElementById("company-name") as HTMLInputElement;
            if (!companyName.value) {
                errors.push("Company name is requried");
                setValidationErrors(errors);
            }
    
            const logo = document.getElementById("logo") as HTMLInputElement;
            if (logo.files?.length) {
                const file = logo.files[0];
                if (file.size > maxLogoByteSize) {
                    errors.push("Company logo size cannot be greater than 2 MB");
                    setValidationErrors(errors);
                }
            }
    
            if (errors.filter(x => x != "").length > 0) {
                setShowErrors(true);
                return;
            }
    
            authService.post(`${ApplciationSettings.webApiUrl()}/company/create-company`, {
                companyName: companyName.value,
                logo: logo.files?.length ? logo.files[0] : [],
              },
              {
                headers: {
                'Content-Type': 'multipart/form-data'
              }
            },
              function (response: AxiosResponse<Company>) {
                if (!response.data) {
                  alert("not saved");
                } 
                else 
                {
                //   setCompanyName(companyName.value);
                  if (response.data.logoBase64) {
                    // setCompanyLogo(response.data.logoBase64);
                  }
                }
             },
             function (error) {
                console.log(error);
             });
        };

        const handleCancelCompanyEdit = () => {
            setShowEditCompanyDialog(false);
            setValidationErrors([""]);
            setShowErrors(false);
        };

        return (<>
        <ProfileDialog/>
        <Dialog
            open={showEditCompanyDialog}
            onClose={handleCloseLogin}
            aria-labelledby="responsive-dialog-title">
            <DialogTitle id="responsive-dialog-title">
                <span style={{ padding: "20px" }} className='flex-column'>
                    <ValidationErrors/>
                    <span className='bold'>Edit Company Info <ApartmentIcon/></span> 
                </span>
            </DialogTitle>
            <form className='flex-column sign-in-controls-column' style={{ margin: "0px 40px 40px 40px" }}>
                <TextField
                    required
                    autoComplete='company-name'
                    id="company-name"
                    className='form-sign-on-control'
                    label="Company Name"
                    defaultValue={currentUser?.team?.company?.name}
                    variant="standard"
                />
                <span className='form-sign-on-control flex-column'>
                    <span>Logo</span>
                    <TextField id="logo" type="file" />
                </span>
            </form>
            <DialogActions className='flex-row-center'>
                <Button autoFocus onClick={handleSaveCompanyEdit}>
                    <span>Save</span>
                </Button>
                <Button autoFocus onClick={handleCancelCompanyEdit}>
                    <span>Cancel</span>
                </Button>
            </DialogActions>
        </Dialog>
       </>
        );
    }


    function EditCompanyInfoMenu() {
        if (currentUser && currentUser.roleName == "Owner") {

            const handleOpenCompanyEdit = () => {
                setShowEditCompanyDialog(true);
                setShowMenuProfileOpen(false);
            };

            return (<>
                <MenuItem onClick={handleOpenCompanyEdit}>Company Profile</MenuItem>
            </>);
        }
        return (<></>);
    }


    const handleClickMenuProfile = (event: React.MouseEvent<HTMLButtonElement>) => {
        setAnchorEl(event.currentTarget);
        setShowMenuProfileOpen(true);
    };

    const handleCloseProfileMenu = () => {
        setAnchorEl(null);
        setShowMenuProfileOpen(false);
    };

    const handleOpenProfile = () => {
        setShowEditProfileDialog(true);
        setShowMenuProfileOpen(false);
    };

    const handleSignOut = () => {
        let authService = new AuthService();
        authService.post(`${ApplciationSettings.webApiUrl()}/account/sign-out`, {}, {}, 
        function (response) {
            localStorage.removeItem("ACCESS_TOKEN");
            localStorage.removeItem("REFRESH_ACCESS_TOKEN");
            navigateTo("/");
         },
         function (error) {
            console.log(error);
         });
    }

    return (<>
        <div className='user-profile'>
            <IconButton 
                    id="basic-button"
                    aria-controls={showMenuProfileOpen ? 'basic-menu' : undefined}
                    aria-haspopup="true"
                    color="primary"
                    aria-expanded={showMenuProfileOpen ? 'true' : undefined}
                    onClick={handleClickMenuProfile}>
                <AccountCircleIcon/>
            </IconButton>
            <Menu
                id="basic-menu"
                anchorEl={anchorEl}
                open={showMenuProfileOpen}
                onClose={handleCloseProfileMenu}
                MenuListProps={{
                'aria-labelledby': 'basic-button',
                }}
            >
                <MenuItem onClick={handleOpenProfile}>Account Profile</MenuItem>
                <EditCompanyInfoMenu/>
                <MenuItem onClick={handleSignOut}>Logout</MenuItem>
            </Menu>
        </div>
        <EditCompanyDialog/>
    
    </>);
}

export default UserProfileInfoDialog;