import WorkSpaceNavBar from "./workspace-navbar";
import './workspace-main.css'
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import { useEffect, useReducer, useRef, useState, useCallback } from 'react';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import InputLabel from '@mui/material/InputLabel';
import { Backdrop, Dialog, DialogActions, DialogTitle, NativeSelect, Popover, TextField, Typography } from "@mui/material";
import { AuthService } from "../../services/auth/auth-service";
import { useNavigate } from "react-router-dom";
import { InviteStatus, User } from "../../models/user";
import dayjs, { Dayjs } from 'dayjs';
import axios, { AxiosResponse } from "axios";
import CircularProgress from '@mui/material/CircularProgress';
import RequestTimeOffDialog from "../shared/add-time-off-request-dialog";
import { TimeOff, TimeOffType } from "../../models/time-off";
import LocalHotelIcon from '@mui/icons-material/LocalHotel';
import BeachAccessIcon from '@mui/icons-material/BeachAccess';
import { TimeOffService } from "../../services/time-off-service";
import { CompanyService } from "../../services/auth/company-service";

function WorkSpaceMain() {

    const [selectedTeamId, setSelectedTeamId] = useState(0);
    const [selectedTeamLabel, setSelectedTeamLabel] = useState("");
    const [showBackDrop, setShowBackDrop] = useState(false);
    const [showTimeOffRequest, setShowTimeOffRequest ] = useState(false);
    const [showViewTimeOff, setShowViewTimeOff ] = useState(false);
    const [anchorViewTimeOff, setAnchorViewTimeOff] = useState<HTMLButtonElement | null>(null);

    const [usersInTeam, setUsersInTeam] = useState<User[]>([]);
    const selectedTimeOffDay = useRef("");
    const selectedMonth = useRef("");
    const [usersTimeOffs, setUsersTimeOffs] = useState<[id:number, timeOffs: TimeOff[]][]>([]);

    
    let defaultUser: User = {
        id:0,
        tookAllowanceTimeOff:0,
        totalAllowanceTimeOffInYear:0,
        birthDate: new Date(),
        startWorkDate: new Date(),
        lastName: "",
        firstName:"",
        email:"",
        teamId:0,
        roleName: "",
        team: null,
        inviteStatus: InviteStatus.None
    };
    const [currentUser, setCurrentUser] = useState<User>(defaultUser);

    const navigateTo = useNavigate();

    useEffect(() => {
        let authService = new AuthService();
        let timeOffService = new TimeOffService();
        let companyService = new CompanyService();
        if (currentUser == null || currentUser.id == 0) {
            authService.getUserIfAuthorized({}, (user:AxiosResponse<User>) => {
                if (!user?.data) {
                     navigateTo("/");
                } else {
                    setCurrentUser(user.data);
                    if (user.data?.team) {
                        let currentDate = new Date();
                        let currentYear = currentDate.getFullYear();
                        let currentMonth = currentDate.getMonth();
                        timeOffService.getTimeOffsByUserAndMonths(
                        {
                            userId: user.data.id,
                            months: [currentMonth, currentMonth+1],
                            isApproved: false,
                            year: currentYear
                        },{}, async (resp:AxiosResponse<TimeOff[]>) => {
                            if (user.data.id) {
                                let timeOffs = usersTimeOffs;
                                timeOffs.push([user.data.id, resp.data]);
                                setUsersTimeOffs(timeOffs);
                                let allReq = [];
                                
                                if (user.data.team?.users) {
                                for (let i = 0; i < user.data.team?.users.length; i++) {
                                    allReq.push(
                                        authService.post("http://localhost:5122/timeOff/get-time-offs-by-user-and-months", 
                                        {
                                            userId: user.data.team?.users[i].id,
                                            months: [currentMonth, currentMonth+1],
                                            isApproved: true,
                                            year: currentYear
        
                                        },{}, (resp:AxiosResponse<TimeOff[]>) => {
                                            if (user.data.team?.users[i].id) {
                                                let timeOffs = usersTimeOffs;
                                                timeOffs.push([user.data.team?.users[i].id, resp.data]);
                                                setUsersTimeOffs(timeOffs);
                                            }
                                        }, (err) => console.log(err))
                                    );
                                }
                                await Promise.all(allReq);
                            }
                            }
                        }, (err) => console.log(err));
                    }
                }

            }, function (error) {
                console.log(error);
            });
        }
        if (currentUser.id != 0 && (!usersInTeam || usersInTeam.length == 0) ) {
            companyService.getCompanyUsers({}, 
            (resp: AxiosResponse<User[]>) => {
                setUsersInTeam(resp.data);
            },
            function (error) {
                console.log(error);
            }, currentUser.team?.companyId);
        }
    });

    function daysInMonth(month:number, year:number) {
        return new Date(year, month, 0).getDate();
    }

    function getTimeOffIconFromType(type: TimeOffType) {
        switch (type) {
            case TimeOffType.Vacation: {
                return <BeachAccessIcon color="secondary"/>;
            }
            case TimeOffType.SickLeave: {
                return <LocalHotelIcon/>;
            }
            default: {
                return <></>;
            }
        }
    }

    function ViewTookTimeOffPopuv({id}: {id:string}) {

        const handleClosePopeverTimeOff = () => {
            setAnchorViewTimeOff(null);
        };

        return <>
            <Popover
                id={id}
                open={showViewTimeOff}
                anchorEl={anchorViewTimeOff}
                onClose={handleClosePopeverTimeOff}
                anchorOrigin={{
                    vertical: 'bottom',
                    horizontal: 'left',
                }}
                >
                <Typography sx={{ p: 2 }}>The content of the Popover.</Typography>
            </Popover>
        </>;
    }

    function TeamsTimeOffTable() {

        function CalendarDaysRows() {
            let showDays = 30;
            let currentDate = new Date();
            let currentMonth = currentDate.getMonth();
            let dayOfMonth = currentDate.getDate();
            let year = currentDate.getFullYear();
            let isNextMonth = false;

            let jsx = [];
            let jsxDays = [];
 
            const openRequestTime = (e:any, data:any) => {
                selectedTimeOffDay.current = e.target.innerText;
                let month = e.target.getAttribute("data-month");
                selectedMonth.current = month;
                setShowTimeOffRequest(true);
            };

            for (let i = 0; i < usersInTeam.length; i++) {
                currentMonth = currentDate.getMonth();
                jsxDays = [];
                if (currentUser.id == usersInTeam[i].id) {
                    jsxDays.push(
                        <TableCell key={"userName"+i} align="left">
                            <b key={"user-btn"+i.toString()}>{usersInTeam[i].email}</b>
                        </TableCell>
                    );
                } else {
                    jsxDays.push(
                        <TableCell key={"userName"+i} align="left">
                            <p key={"user-btn"+i.toString()}>{usersInTeam[i].email}</p>
                        </TableCell>
                    );
                }

                let tookTimeOffs = usersTimeOffs.find(x => x[0] == usersInTeam[i].id)?.[1];

                let showTimeOffIcon = false;
                let timeOffShowType = TimeOffType.SickLeave;
                for (let j = 0; j < showDays; j++) {

                    if (currentUser.id == usersInTeam[i].id) {
                        let myAttr = {'data-month': `${isNextMonth ? currentMonth + 1 : currentMonth}`}
                        let bookTimeOff = tookTimeOffs?.find(x => new Date(x.startDate).getDate() == dayOfMonth);
                        timeOffShowType = bookTimeOff && bookTimeOff.type ? bookTimeOff.type : TimeOffType.SickLeave;
                        if ((tookTimeOffs && bookTimeOff != null) 
                                || showTimeOffIcon) 
                        {
                            showTimeOffIcon = true;

                            let classTimeOff = bookTimeOff?.isApproved ? "calendar-cell-timeOff-approved" : "calendar-cell-timeOff-not-approved";
                            
                            const handleViewTimeOffClick = () => {
                                setShowViewTimeOff(true);
                            };

                            jsxDays.push(
                                <>
                                    <TableCell onClick={handleViewTimeOffClick} className={classTimeOff} key={j.toString() + i.toString() + "day"} align="center">
                                        <a key={j.toString() + i.toString() + "day-btn"}> {getTimeOffIconFromType(timeOffShowType)}</a>
                                    </TableCell>
                                </>
                            );
                            if (tookTimeOffs?.find(x => new Date(x.endDate).getDate() == dayOfMonth) != null) {
                                showTimeOffIcon = false;
                            }

                        } else {
                            jsxDays.push(
                                <>
                                    <TableCell {...myAttr} onClick={(e:any,data:any) => openRequestTime(e,data)} 
                                        {...myAttr} className="calendar-cell" key={j.toString() + i.toString() + "day:"} align="center">
                                        <a {...myAttr} key={j.toString() + i.toString() + "day-btn"}>{dayOfMonth}</a>
                                    </TableCell>
                                </>
                            );
                        }
                    } else {
                        let bookTimeOff = tookTimeOffs?.find(x => new Date(x.startDate).getDate() == dayOfMonth);
                        timeOffShowType = bookTimeOff && bookTimeOff.type ? bookTimeOff.type : TimeOffType.SickLeave;
                        if ( (tookTimeOffs && tookTimeOffs?.find(x => new Date(x.startDate).getDate() == dayOfMonth) != null) 
                        || showTimeOffIcon ) 
                        {
                            let classTimeOff = bookTimeOff?.isApproved ? "calendar-cell-timeOff-approved" : "calendar-cell-timeOff-not-approved";

                            const handleViewTimeOffClick = () => {
                                setShowViewTimeOff(true);
                            };

                            jsxDays.push(
                                <>
                                    <TableCell onClick={handleViewTimeOffClick} className={classTimeOff} key={j.toString() + i.toString() + "day"} align="center">
                                        <a key={j.toString() + i.toString() + "day-btn"}>{getTimeOffIconFromType(timeOffShowType)}</a>
                                    </TableCell>
                                </>
                            );
                            if (tookTimeOffs?.find(x => new Date(x.endDate).getDate() == dayOfMonth) != null) {
                                showTimeOffIcon = false;
                            }
                        }
                         else 
                         {
                            jsxDays.push(
                                <>
                                    <TableCell className="calendar-cell" key={j.toString() + i.toString() + "day"} 
                                        onClick={(e:any,data:any) => openRequestTime(e,data)}
                                        align="center">
                                        <a key={j.toString() + i.toString() + "day-btn"}>{dayOfMonth}</a>
                                    </TableCell>
                                </>
                            );
                        }
                    }
                    dayOfMonth++;
                    let maxDays = daysInMonth(currentMonth, year);
                    if (dayOfMonth > maxDays) {
                        dayOfMonth = 1;
                        isNextMonth = true;
                    }
                }
                jsx.push(
                        <TableRow
                            key={"row-" + i}
                            sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                            {jsxDays}
                        </TableRow>
                      );
            }
            return (<>{jsx}</>);
        }

        function CalendarDaysColumns() {
            let currentDate = new Date();
       
            const daysLabels = new Map();
            daysLabels.set(1, "M");
            daysLabels.set(2, "T");
            daysLabels.set(3, "W");
            daysLabels.set(4, "T");
            daysLabels.set(5, "F");
            daysLabels.set(6, "S");
            daysLabels.set(7, "S");
            let dayOfWeek = currentDate.getDay();
            let daysToShow = 30;
            let jsx = [];
            for (let i = 0; i < daysToShow; i++) {
                let label = daysLabels.get(dayOfWeek);
                jsx.push(<TableCell size="small" key={i+"label-column"} align="center"><Button variant="text">{label}</Button></TableCell>);
                dayOfWeek++;
                if (dayOfWeek == 8) {
                    dayOfWeek = 1;
                }
            }

            return (<>{jsx}</>);
        }

        const handleCloseBackDrop = () => {
            setShowBackDrop(false);
        };
          
        return (<>
                <TableContainer component={Paper}>
                    <Table aria-label="simple table">
                        <TableHead>
                            <TableRow>
                                <TableCell>Team member</TableCell>
                                <CalendarDaysColumns/>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            <CalendarDaysRows/>
                        </TableBody>
                    </Table>
                </TableContainer>
                <Backdrop
                    sx={{ color: '#fff', zIndex: (theme:any) => theme.zIndex.drawer + 1 }}
                    open={showBackDrop}
                    onClick={handleCloseBackDrop}
                >
                    <CircularProgress color="inherit" />
                </Backdrop>
          </>)
        
    }

    function GetMonthsLabesl(month:number) {
        let months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", 
         "Novermber", "December"];
         return months[month];
    }

    let tableMonth = "";

    if (!tableMonth) {
        let currentDate = new Date();
        let currentMonth = currentDate.getMonth();
        let dayOfMonth = currentDate.getDate();

        let monthLabelCurrent = GetMonthsLabesl(currentMonth);
        let nextMonthLabel = GetMonthsLabesl(currentMonth + 1);
        if (dayOfMonth == 1) {
            tableMonth = monthLabelCurrent;
        } else {
            tableMonth = monthLabelCurrent + "-" + nextMonthLabel;
        }
    }

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

    // function ViewTimeOffDetailsDialog() {

    //     return 
    //         <Dialog
    //             open={show}
    //             onClose={onClose}
    //             aria-labelledby="responsive-dialog-title"
    //             >
    //             <DialogTitle id="responsive-dialog-title">
    //                 {/* <span style={{ padding: "20px" }} className='flex-column'> */}
    //                 <span className='bold'>{currentUser.firstName + " " + currentUser.lastName} 
                       
    //                 </span>
    //             </DialogTitle>
    //             <form className='flex-column sign-in-controls-column' style={{ margin: "0px 40px 40px 40px" }}>
    //                 <div>
    //                     <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
    //                         <div className="flex-row">
    //                             <Box sx={{ marginTop: "10px", marginBottom: "10px", marginRight:"20px" }}>
    //                                 <InputLabel style={{ color: "black"}} id="team-select-label">Start date </InputLabel>
                                    
    //                             </Box>
    //                             <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
    //                                 <InputLabel style={{ color: "black"}} id="team-select-label">Start time </InputLabel>
                                    
    //                             </Box>
    //                         </div>
    //                     </Box>
    //                     <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
    //                         <div className="flex-row">
    //                         <Box sx={{ marginTop: "10px", marginBottom: "10px", marginRight:"20px" }}>
    //                             <InputLabel style={{ color: "black"}} id="team-select-label">End date </InputLabel>
                                
    //                         </Box>
    //                         <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
    //                             <InputLabel style={{ color: "black"}} id="team-select-label">End time </InputLabel>
                                
    //                         </Box>
    //                         </div>
    //                     </Box>
    //                 </div>
    //             </form>
    //             <DialogActions className='flex-row-center'>
    //                 <Button onClick={sumbit} autoFocus>
    //                     <span>Send Request</span>
    //                 </Button>
    //             </DialogActions>
    //         </Dialog>;
        
    // }

    const handleChangeTeam = (event: React.ChangeEvent) => {
        let id = event.target.nodeValue ? +event.target.nodeValue : 0;
        setSelectedTeamId(id);
        let team = currentUser.team?.company?.teams.find(x => x.id == id);
        setSelectedTeamLabel(team?.name ?? "");
    };

    const closeTimeOffRequest = () => {
        setShowTimeOffRequest(false);
    };

    const onTimeOffSubmit = () => {
        let requestType = document.getElementById("request-select-type") as HTMLSelectElement;

        let sDateStr = (document.getElementById("start-date-off") as HTMLInputElement).value;
        let endDateStr = (document.getElementById("end-date-off") as HTMLInputElement).value;
        let sTimeStr = (document.getElementById("start-time-off") as HTMLInputElement).value;
        let endTimeStr = (document.getElementById("end-time-off") as HTMLInputElement).value;

        let startDate = new Date(sDateStr);
        let endDate = new Date(endDateStr);

        let formatedStart = new Date();
        if (sTimeStr) {
            let timeParsed = dayjs(sTimeStr, "HH:mm");
            let timeParsedDate = timeParsed.toDate();
            formatedStart = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDay(), timeParsedDate.getHours(),
            timeParsedDate.getMinutes(), timeParsedDate.getSeconds());
        } else {
            formatedStart = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDay(), 0,
                0, 0);
        }

        let formatedEnd = new Date();

        if (endTimeStr) {
            let timeParsed = dayjs(endTimeStr, "HH:mm");
            let timeParsedDate = timeParsed.toDate();
            formatedEnd = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDay(), timeParsedDate.getHours(),
                timeParsedDate.getMinutes(), timeParsedDate.getSeconds());
        } else {
            formatedEnd = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDay(), 0,
                0, 0);
        }

        let note = document.getElementById("time-off-note") as HTMLInputElement;

        let authService = new AuthService();

        authService.post(`http://localhost:5122/timeOff/add-time-off`, 
            {
                teamId: currentUser.teamId,
                type: +requestType.value,
                startDate: formatedStart,
                endDate: formatedEnd,
                note: note.value,
                employeeId: currentUser.id
            }
        ,{}, (res:AxiosResponse<TimeOff>) =>  {

            setShowTimeOffRequest(false);

        }, (err) => console.log(err));
    };

    return (<>
            <WorkSpaceNavBar/>
            <div style={{ padding: "50px" }}>
                <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
                    <InputLabel style={{ color: "black"}} id="team-select-label">Team </InputLabel>
                    <NativeSelect
                        defaultValue={30}
                        onChange={handleChangeTeam}
                        inputProps={{
                            name: 'team',
                            id: 'select-team',
                        }}
                        >
                        <GetTeams/>
                    </NativeSelect>
                    <p style={{ color:"black", textAlign:"center" }}>{tableMonth}</p>
                </Box>
                <TeamsTimeOffTable/>
                <RequestTimeOffDialog show={showTimeOffRequest}
                    onSubmit={onTimeOffSubmit}
                    selectedDay={selectedTimeOffDay}
                    selectedMonth={selectedMonth}
                    closeTimeOff={closeTimeOffRequest}
                    currentUser={currentUser}/>
            </div>
    </>);
}

export default WorkSpaceMain;