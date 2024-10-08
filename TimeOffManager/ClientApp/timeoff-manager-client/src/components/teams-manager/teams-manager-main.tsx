import TeamsManagerFooter from "./teams-manager-footer";
import TeamsManagerNavbar from "./teams-manager-navbar";
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import { Fragment, useEffect, useState } from "react";
import { InviteStatus, User } from "../../models/user";
import { AuthService } from "../../services/auth/auth-service";
import { useNavigate } from "react-router-dom";
import { Alert, AlertTitle, Badge, Box, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, InputLabel, NativeSelect, TextField } from "@mui/material";
import AccessTimeFilledIcon from '@mui/icons-material/AccessTimeFilled';
import "./teams-manager-main.css"
import Tooltip from '@mui/material/Tooltip';
import Person4Icon from '@mui/icons-material/Person4';
import CreateIcon from '@mui/icons-material/Create';
import DeleteIcon from '@mui/icons-material/Delete';
import axios, { AxiosResponse } from "axios";
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import { CompanyService } from "../../services/auth/company-service";
import { ApplciationSettings } from "../../models/application-settings";
import { TeamsManagerProvider, useSharedTeamsData } from "./teams-manager-cxt";

function TeamsManagerMain() {

    const [usersInTeam, setUsersInTeam] = useState<User[]>([]);
    const [selectedTeamId, setSelectedTeamId] = useState(0);
    const [selectedTeamLabel, setSelectedTeamLabel] = useState("None");
    const [showErrors, setShowErrors] = useState(false);
    const [showEditTeamName, setShowEditTeamName] = useState(false);
    const [showAddTeamate, setShowAddTeamate] = useState(false);
    const [validationErrors, setValidationErrors] = useState([""]);
    const { data } = useSharedTeamsData();

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
    const [editedUser, setEditUser] = useState<User>(defaultUser);
    const [showEditUser, setShowEditUser] = useState(false);
    const [showDeleteConfirmUser, setShowDeleteConfirmUser] = useState(false);
    const [userIdFromDeleteDialog, setUserIdFromDeleteDialog] = useState(0);
    const [currentUser, setCurrentUser] = useState<User>(defaultUser);
    const navigateTo = useNavigate();
    
    useEffect(() => {
        let authService = new AuthService();
        let companyService = new CompanyService();
        if (currentUser == null || currentUser.id == 0) {
            authService.getUserIfAuthorized({}, (user:AxiosResponse<User>) => {
                if (!user?.data) {
                     navigateTo("/");
                } else {
                    if (user.data.roleName != "Owner") {
                        navigateTo("/workspace");
                    }
                    setCurrentUser(user.data);
                    setSelectedTeamId(user.data?.teamId);
                    setSelectedTeamLabel(user.data?.team?.name ?? "");
                }

            }, function (error) {
                console.log(error);
            });
        }
        if (currentUser.id != 0 && usersInTeam.length == 0 && currentUser.team?.companyId) {
            companyService.getCompanyUsers({}, 
             (users:AxiosResponse<User[]>) => {
                if (!users?.data) {
                } else {
                    setUsersInTeam(users.data);
                }

            }, function (error) {
                console.log(error);
            }, currentUser.team?.companyId);
        }
    });

    function AddTeamateDialog() {

        const handleCloseAddTeamate = () => {
            setShowAddTeamate(false);
        };

        const handleSendInvite = () => {
            let errors = [];

            let fName = document.getElementById("new-f-name") as HTMLInputElement;

            if (!fName.value) {
                errors.push("First name is requried");
            }

            let lName = document.getElementById("new-l-name") as HTMLInputElement;
            if (!lName.value) {
                errors.push("Last name is requried");
            }
            let email = document.getElementById("new-email") as HTMLInputElement;

            if (!email.value) {
                errors.push("Email is requried");
            }

            if (errors.length) {
                setShowErrors(true);
                setValidationErrors(errors);
                return;
            }

            axios.post(`${ApplciationSettings.webApiUrl()}/company/send-invite`, {
                firstName: fName.value,
                lastName: lName.value,
                email: email.value,
                teamId: selectedTeamId
            }, {}).then((resp: AxiosResponse<User>) => {
                let updUsersInTeam = usersInTeam;
                updUsersInTeam.push(resp.data);
                setUsersInTeam(updUsersInTeam);
                setShowAddTeamate(false);
            });
        };

        return (<>

            <Dialog
                open={showAddTeamate}
                onClose={handleCloseAddTeamate}
                aria-labelledby="responsive-dialog-title">
                <DialogTitle id="responsive-dialog-title">
                    <span style={{ padding: "20px" }} className='flex-column'>
                        <ValidationErrors/>
                        <span className='bold'>Add a new user</span> 
                    </span>
                </DialogTitle>
                <form className='flex-column' style={{ margin: "0px 40px 40px 40px" }}>
                        <TextField
                            autoComplete='nFName'
                            required
                            id="new-f-name"
                            margin="normal"
                            label="First Name"
                            defaultValue={""}
                            type="text"
                            variant="standard"
                        />
                        <TextField
                            autoComplete='nLName'
                            required
                            id="new-l-name"
                            margin="normal"
                            label="Last Name"
                            defaultValue={""}
                            type="text"
                            variant="standard"
                        />
                        <TextField
                            autoComplete='nEmail'
                            required
                            id="new-email"
                            margin="normal"
                            label="Email"
                            defaultValue={""}
                            type="text"
                            variant="standard"
                        />
                        <small>An invite will be sent to provided email</small>
                </form>
                <DialogActions className='flex-row-center'>
                    <Button autoFocus onClick={handleSendInvite}>
                        <span>Send invite</span>
                    </Button>
                    <Button autoFocus onClick={handleCloseAddTeamate}>
                        <span>Cancel</span>
                    </Button>
                </DialogActions>
            </Dialog>
        </>);

    }

    function DeleteConfirmDialog() {

        const handleCloseDeleteConfirm = () => {
            setShowDeleteConfirmUser(false);
        };

        const handleDeleteUser = () => {
            axios.delete(`${ApplciationSettings.webApiUrl()}/company/remove-from-team?userId=${userIdFromDeleteDialog}`, {}).then(() => {
                setShowDeleteConfirmUser(false);
                let usersInTeamUpd = usersInTeam.filter(x => x.id != userIdFromDeleteDialog); 
                setUsersInTeam(usersInTeamUpd);
            });
        };

        return (<>
        <Fragment>
            <Dialog
                open={showDeleteConfirmUser}
                onClose={handleCloseDeleteConfirm}
                aria-labelledby="alert-dialog-title"
                aria-describedby="alert-dialog-description">
                <DialogTitle id="alert-dialog-title">
                    {"Confirm"}
                </DialogTitle>
                <DialogContent>
                <DialogContentText id="alert-dialog-description">
                    This user will be deleted from a team.
                </DialogContentText>
                </DialogContent>
                <DialogActions>
                <Button onClick={handleCloseDeleteConfirm}>Cancel</Button>
                <Button onClick={handleDeleteUser} autoFocus>
                    Delete
                </Button>
                </DialogActions>
            </Dialog>
        </Fragment>
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

    function EditTeamNameDialog() {

        const handleCloseTeamNameEdit = () => {
            setShowEditTeamName(false);
        };

        const handleEditTeamName = () => {
            let updatedName = document.getElementById("team-name") as HTMLInputElement;
            axios.patch(`${ApplciationSettings.webApiUrl()}/company/edit-company-name?id=${selectedTeamId}&teamName=${encodeURIComponent(updatedName.value)}`, {
                
            }, {}).then(() => {
                if (currentUser.team) {
                    let editedTeam = currentUser.team.company.teams.find(x => x.id == selectedTeamId);
                    if (editedTeam) {
                        let index = currentUser.team?.company.teams.indexOf(editedTeam);
                        editedTeam.name = updatedName.value;
                        currentUser.team.company.teams[index] = editedTeam;
                    }
                }
                setShowEditTeamName(false);
                setSelectedTeamLabel(updatedName.value);
            });
        };

        return (<>
        
        <Dialog
                open={showEditTeamName}
                onClose={handleCloseTeamNameEdit}
                aria-labelledby="responsive-dialog-title">
                <DialogTitle id="responsive-dialog-title">
                    <span style={{ padding: "20px" }} className='flex-column'>
                        <ValidationErrors/>
                        <span className='bold'>Edit team's name</span> 
                    </span>
                </DialogTitle>
                <form className='flex-column' style={{ margin: "0px 40px 40px 40px" }}>
                        <TextField
                            autoComplete='team-name'
                            id="team-name"
                            margin="normal"
                            label="Team name"
                            defaultValue={data ? data : selectedTeamLabel}
                            type="text"
                            variant="standard"
                        />
                </form>
                <DialogActions className='flex-row-center'>
                    <Button autoFocus onClick={handleEditTeamName}>
                        <span>Save</span>
                    </Button>
                    <Button autoFocus onClick={handleCloseTeamNameEdit}>
                        <span>Cancel</span>
                    </Button>
                </DialogActions>
            </Dialog>
        
        </>);
    }

    function EditUserDialog() {

        const handleCloseEditUser = () => {
            setShowEditUser(false);
        };

        const handleEditUser = () => {
            let totalTimeOff = document.getElementById("total-time-off") as HTMLInputElement;
            let tookTimeOff = document.getElementById("took-time-off") as HTMLInputElement;

            axios.patch(`${ApplciationSettings.webApiUrl()}/account/update-allowance-timeoff`, 
            {
                userId: editedUser.id,
                totalTimeOff: totalTimeOff.value,
                tookTimeOff: tookTimeOff.value
            }, 
            {}).then(() => {

                let indexUpdatedUser = usersInTeam.indexOf(editedUser);
                editedUser.totalAllowanceTimeOffInYear = totalTimeOff.value ? +totalTimeOff.value : 0;
                editedUser.tookAllowanceTimeOff = tookTimeOff.value ?  +tookTimeOff.value : 0;
                usersInTeam[indexUpdatedUser] = editedUser;
                setShowEditUser(false);
            });
        };

        return (<>

            <Dialog
                open={showEditUser}
                onClose={handleCloseEditUser}
                aria-labelledby="responsive-dialog-title">
                <DialogTitle id="responsive-dialog-title">
                    <span style={{ padding: "20px" }} className='flex-column'>
                        <ValidationErrors/>
                        <span className='bold'>Edit {editedUser.email}</span> 
                    </span>
                </DialogTitle>
                <form className='flex-column' style={{ margin: "0px 40px 40px 40px" }}>
                        <TextField
                            autoComplete='total-time-off'
                            id="total-time-off"
                            margin="normal"
                            label="Total allowance time off"
                            defaultValue={editedUser.totalAllowanceTimeOffInYear}
                            type="number"
                            variant="standard"
                        />
                        <TextField
                            autoComplete='took-time-off'
                            id="took-time-off"
                            margin="normal"
                            label="Took allowance time off"
                            defaultValue={editedUser.tookAllowanceTimeOff}
                            type="number"
                            variant="standard"
                        /> 
                </form>
                <DialogActions className='flex-row-center'>
                    <Button autoFocus onClick={handleEditUser}>
                        <span>Save</span>
                    </Button>
                    <Button autoFocus onClick={handleCloseEditUser}>
                        <span>Cancel</span>
                    </Button>
                </DialogActions>
            </Dialog>

        </>);
    }

    function TeamsRows() {

        let jsx = [];
        let jsxValues = [];

        function UserEmailWithStatus({user}: {user:User}) {
            if (user.inviteStatus == InviteStatus.WaitForAccept) {
                return (<>
                
                    <Tooltip title="Waiting for to accept invite to team">
                        <Badge badgeContent={
                            <AccessTimeFilledIcon style={{ fontSize:"15px" }} fontSize="small"/>} 
                            color="primary">
                            <p>{user.email}</p>
                        </Badge>
                    </Tooltip>
                
                </>);
            }

            if (user.roleName == "Owner") {
               return (<>
                    <Tooltip title="Owner">
                        <Badge badgeContent={
                            <Person4Icon style={{ fontSize:"15px" }} fontSize="small"/>} 
                                color="primary">
                                <p>{user.email}</p>
                        </Badge>
                    </Tooltip>
                </>);
            }

            return (<p>{user.email}</p>);
        }

        for (let i = 0; i < usersInTeam.length; i++) {

            jsxValues = [];

            jsxValues.push(
                <TableCell align="center" key={i + "fname"}>
                    <p>{usersInTeam[i].firstName}</p>
                </TableCell>
            );
            jsxValues.push(
                <TableCell key={i + "lname"} align="center">
                    <p>{usersInTeam[i].lastName}</p>
                </TableCell>
            );
            jsxValues.push(
                <TableCell key={i + "email"} align="center">
                     <UserEmailWithStatus user={usersInTeam[i]}/>
                </TableCell>
            );
            jsxValues.push(
                <TableCell key={i + "start-work"} align="center">
                    <p>{new Date(usersInTeam[i].startWorkDate).toDateString()}</p>
                </TableCell>
            );
            jsxValues.push(
                <TableCell key={i + "birthDate"} align="center">
                    <p>{new Date(usersInTeam[i].birthDate).toDateString() }</p>
                </TableCell>
            );
            jsxValues.push(
                <TableCell key={i + "total-allowance"} align="center">
                    <p>{usersInTeam[i].totalAllowanceTimeOffInYear}</p>
                </TableCell>
            );
            jsxValues.push(
                <TableCell key={i + "took allowance"} align="center">
                    <p>{usersInTeam[i].tookAllowanceTimeOff}</p>
                </TableCell>
            );

            const handleEditUser = (user:User) => {
                setShowEditUser(true);
                setEditUser(user);
            };

            const handleRemoveUserFromTeam = (userId: number) => {
                setUserIdFromDeleteDialog(userId);
                setShowDeleteConfirmUser(true);
            };

            if (usersInTeam[i].roleName != "Owner") {
                jsxValues.push(
                    <TableCell key={i + "edit"} align="center">
                        <Button onClick={() => handleEditUser(usersInTeam[i])} variant="outlined" startIcon={<CreateIcon />}>
                                Edit
                        </Button>
                        <Button style={{ marginLeft:"5px" }} color="error" 
                        onClick={() => handleRemoveUserFromTeam(usersInTeam[i].id)} variant="outlined" 
                            startIcon={<DeleteIcon />}>
                                Delete
                        </Button>
                    </TableCell>
                );
            } else {
                jsxValues.push(
                    <TableCell key={i + "edit"} align="center">
                        <Button onClick={() => handleEditUser(usersInTeam[i])} variant="outlined" startIcon={<CreateIcon />}>
                                Edit
                        </Button>
                    </TableCell>
                );
            }

            jsx.push(
                <TableRow
                    key={"row-user-team-" + i}
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                    {jsxValues}
                </TableRow>
            );
        }

        return (<>{jsx}</>);
    }

    function TeamsTable() {
        return (<>    
            <TableContainer component={Paper}>
                <Table sx={{ minWidth: 650 }} aria-label="simple table">
                    <TableHead>
                        <TableRow>
                            <TableCell align="center">First Name</TableCell>
                            <TableCell align="center">Last Name</TableCell>
                            <TableCell align="center">Email</TableCell>
                            <TableCell align="center">Start working date</TableCell>
                            <TableCell align="center">Birthday</TableCell>
                            <TableCell align="center">Total free time offs</TableCell>
                            <TableCell align="center">Took time offs</TableCell>
                            <TableCell align="center">Edit</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        <TeamsRows/>
                    </TableBody>
                </Table>
            </TableContainer> 
        </>);
    }

    const handleChangeTeam = (event:any) => {
        setSelectedTeamLabel(event.target.value as string);
    };

    function GetTeams() {
        let jsx = [];
        let totalTeams = currentUser.team?.company?.teams?.length ?? 0;
        for (let i =0; i < totalTeams; i++) {
            jsx.push(
                 <option key={currentUser.team?.company?.teams[i].id}
                    value={currentUser.team?.company?.teams[i].id}>{currentUser.team?.company?.teams[i].name}</option>
            );
        }
        return <>{jsx}</>;
    }

    const handleEditTeamName = () => {
        setShowEditTeamName(true);
    };

    const handleAddTeamate = () => {
        setShowAddTeamate(true);
    };

    let showEditTeam = <></>;
    if (selectedTeamId) {
        showEditTeam = <span style={{marginLeft: "10px", cursor: "pointer"}}>
            <Tooltip title="Edit team's name">
                <CreateIcon onClick={handleEditTeamName} color="primary"/>
            </Tooltip>
        </span>;
    }
    let showAddNewUser = <></>;
    if (selectedTeamId) {
        showAddNewUser =  <Button onClick={handleAddTeamate} variant="outlined" startIcon={<AddCircleOutlineIcon />}>
                Add a new user
        </Button>;
    }

    return (<>
        <TeamsManagerProvider>
            <TeamsManagerNavbar/>
                <div style={{padding: "20px"}}>
                    <Box sx={{ marginTop: "10px", marginBottom: "10px", display:"flex", justifyContent:"space-between" }}>
                        <span>
                            <span style={{display:"flex", alignItems:"center", gap:"15px"}}>
                                <InputLabel style={{ color: "black"}} id="team-select-label">Team </InputLabel>
                                <NativeSelect
                                    value={selectedTeamLabel}
                                    onChange={handleChangeTeam}>
                                    <option key="none" value="-1">{data ? data : "None"}</option>
                                    <option key="none" value="3">{data ? data : "None3"}</option>
                                    <GetTeams/>
                                </NativeSelect>
                                {showEditTeam}
                            </span>
                        </span>
                        {showAddNewUser}
                    </Box>
                    <TeamsTable/>
                    <EditUserDialog/>
                    <EditTeamNameDialog/>
                    <DeleteConfirmDialog/>
                    <AddTeamateDialog/>
                </div>
            <TeamsManagerFooter/>
        </TeamsManagerProvider>
    </>);
}

export default TeamsManagerMain;