import { Button, ButtonGroup } from '@mui/material';
import { AxiosResponse } from 'axios';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { InviteStatus, User } from '../../models/user';
import { AuthService } from '../../services/auth/auth-service';
import './teams-manager-main.css'
import UserProfileInfoDialog from '../shared/user-profile-info-dialog';
import { Alert, AlertTitle, Dialog, DialogActions, DialogTitle, TextField } 
from "@mui/material"
import { ApplciationSettings } from '../../models/application-settings';
import { useSharedTeamsData } from './teams-manager-cxt';

function TeamsManagerNavbar() {

    const [companyName, setCompanyName] = useState("");
    const [companyLogo, setCompanyLogo] = useState("");
    const [showErrors, setShowErrors] = useState(false);
    const [validationErrors, setValidationErrors] = useState([""]);
    const [showTeamCreate, setShowTeamCreate] = useState(false);
    const [myTeamTabSelected, setMyTeamTabSelected] = useState(true);
    const [createTeamTabSelected, setCreateTeamTabSelected ] = useState(false);
    const { setData  } = useSharedTeamsData();

    let defaultUser: User = {
        id:0,
        lastName: "",
        tookAllowanceTimeOff: 0,
        totalAllowanceTimeOffInYear: 0,
        firstName:"",
        email:"",
        birthDate: new Date(),
        startWorkDate: new Date(),
        teamId:0,
        roleName: "",
        team: null,
        inviteStatus: InviteStatus.None
    };
    const [currentUser, setCurrentUser] = useState<User>(defaultUser);
    let authService = new AuthService();

    const navigateTo = useNavigate();

    useEffect(() => {
        if (currentUser == null || currentUser.id == 0) {
            authService.getUserIfAuthorized({}, (user:AxiosResponse<User>) => {
                if (!user?.data) {
                     navigateTo("/");
                } else {
                    setCurrentUser(user.data);
                    if (user.data.team?.company) {
                        setCompanyName(user.data.team?.company.name);
                    }
                    if (user.data.team?.company.logoBase64) {
                        setCompanyLogo(user.data.team?.company.logoBase64);
                    }
                }

            }, function (error) {
                console.log(error);
            });
        }
    });

    let companyLogoJsx = (<></>);
    if (companyLogo) {
        companyLogoJsx = (<><span className='company-logo'><img src={`data:image/jpeg;base64,${companyLogo}`} width="120px" height="80px" /></span></>);
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

    function CreateTeamDialog() {

        const handleCloseTeamCreate = () => {
            setShowTeamCreate(false);
            setCreateTeamTabSelected(false);
            setMyTeamTabSelected(true);
        };

        const handleAddTeam = () => {
            let teamName = document.getElementById("team-name") as HTMLInputElement;
            authService.post(`${ApplciationSettings.webApiUrl()}/teams/create?name=${encodeURIComponent(teamName.value)}`, {

            }, {}, (resp) => {

                setData(resp.data.team.name);
                setShowTeamCreate(false);

            }, (err) => {} );
        };

        return (<>

            <Dialog
                open={showTeamCreate}
                onClose={handleCloseTeamCreate}
                aria-labelledby="responsive-dialog-title">
                <DialogTitle id="responsive-dialog-title">
                    <span style={{ padding: "20px" }} className='flex-column'>
                        <ValidationErrors/>
                        <span className='bold'>Create Team</span> 
                    </span>
                </DialogTitle>
                <form className='flex-column' style={{ margin: "0px 40px 40px 40px" }}>
                        <TextField
                            required
                            autoComplete='team-name'
                            id="team-name"
                            margin="normal"
                            label="Team name"
                            defaultValue={""}
                            variant="standard"
                        /> 
                </form>
                <DialogActions className='flex-row-center'>
                    <Button autoFocus onClick={handleAddTeam}>
                        <span>Save</span>
                    </Button>
                    <Button autoFocus onClick={handleCloseTeamCreate}>
                        <span>Cancel</span>
                    </Button>
                </DialogActions>
            </Dialog>

        </>);
    }

    const workspaceRedirect = () => {
        navigateTo("/workspace");
    };

    const handleClickCreateTeam = () => {
        setShowTeamCreate(true);
        setCreateTeamTabSelected(true);
        setMyTeamTabSelected(false);
    };

    const handleMyTeam = () => {
        setCreateTeamTabSelected(false);
        setMyTeamTabSelected(true);
    };

    function TeamsTabs() {

        let jsxBtn = <></>;

        if (myTeamTabSelected) {
            jsxBtn = <>
                   <Button variant="contained" onClick={handleMyTeam}>My Team</Button>
                   <Button style={{ marginLeft:"10px" }} variant="outlined" onClick={handleClickCreateTeam}>Create a new team</Button>
            </>
        } 

        if (createTeamTabSelected) {
            jsxBtn = <>
                <Button variant="outlined" onClick={handleMyTeam}>My Team</Button>
                <Button style={{ marginLeft:"10px" }} variant="contained" onClick={handleClickCreateTeam}>Create a new team</Button>
            </>
        }

        let jsx = (<ButtonGroup aria-label="Loading button group">
                        {jsxBtn}
                    </ButtonGroup>);


        return (jsx);
    }

    return (<>
    
        <span className='flex-row-between teams-navbar'>
            <span onClick={workspaceRedirect} style={{ display: "flex", marginLeft: "15px", alignItems:"center", cursor:"pointer" }}>
                {companyLogoJsx}
                <span className='company-name'>{companyName}</span>
            </span>
            <TeamsTabs/>
            <UserProfileInfoDialog 
                currentUser={currentUser}/>
        </span>
        <CreateTeamDialog/>
    </>);
}

export default TeamsManagerNavbar;