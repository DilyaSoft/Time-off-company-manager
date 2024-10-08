import { Button } from '@mui/material';
import { useState, useEffect } from 'react';
import { useNavigate  } from "react-router-dom";
import { AuthService } from '../../services/auth/auth-service';
import { InviteStatus, User } from '../../models/user';
import { AxiosResponse } from 'axios';
import AccessibilityIcon from '@mui/icons-material/Accessibility';
import UserProfileInfoDialog from '../shared/user-profile-info-dialog';


function WorkSpaceNavBar() {

    const [companyName, setCompanyName] = useState("");
    const [companyLogo, setCompanyLogo] = useState("");

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
    const navigateTo = useNavigate();

    useEffect(() => {
        let authService = new AuthService();
        if (currentUser == null || currentUser.id == 0) {
            authService.getUserIfAuthorized({}, 
            (user:AxiosResponse<User>) => {
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

    const workspaceRedirect = () => {
        navigateTo("/workspace");
    };


    const handleTeamsClick = () => {
        navigateTo("/teams-manager");
    };

    function ManageTeamsBtn() {
        if (currentUser.roleName != "Owner") {
            return (<></>);
        }

        return (
            <div>
                <Button onClick={handleTeamsClick} variant="outlined" startIcon={<AccessibilityIcon/>}>
                    Manage Teams
                </Button>
            </div>
        )
    }

    return (<>
            <span className='flex-row-between workspace-navbar'>
                    <span onClick={workspaceRedirect} style={{ display: "flex", marginLeft: "15px", alignItems:"center", cursor:"pointer" }}>
                        {companyLogoJsx}
                        <span className='company-name'>{companyName}</span>
                    </span>
                    <ManageTeamsBtn/>
                    <UserProfileInfoDialog 
                        currentUser={currentUser} />
            </span>
        </>)

}

export default WorkSpaceNavBar;