import { Alert, AlertTitle, Box, Button, Dialog, DialogActions, DialogTitle, InputLabel, MenuItem, NativeSelect, Select, TextareaAutosize } from "@mui/material";
import { DatePicker, LocalizationProvider, TimePicker } from "@mui/x-date-pickers";
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import dayjs, { Dayjs } from 'dayjs';
import { User } from "../../models/user";
import { useState, memo } from "react";
import { TimeOff, TimeOffType } from "../../models/time-off";


function RequestTimeOffDialog({currentUser, show, closeTimeOff, onSubmit, selectedDay, selectedMonth} : {
    currentUser:User, show:boolean, 
    closeTimeOff: () => void, onSubmit: () => void, selectedDay: React.MutableRefObject<string>, 
        selectedMonth: React.MutableRefObject<string>}) {

    let current = new Date();

    const [tookDays, setTookDays] = useState(0);
    const [showErrors, setShowErrors] = useState(false);
    const [validationErrors, setValidationErrors] = useState([""]);

    function TookDays() {

        if (tookDays != 0) {
            return (<>
            
                <p>Requested days: {tookDays}</p>

            </>);
        }

        return <></>;
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

    const sumbit = () => {
        let errors = [];
        setShowErrors(false);
        setValidationErrors([]);
        let startDate = document.getElementById("start-date-off") as HTMLInputElement;

        if (!startDate.value) {
            errors.push("Start date is requried");
        }

        let endDate = document.getElementById("end-date-off") as HTMLInputElement;

        if (!endDate.value) {
            errors.push("End date is requried");
        }

        if (tookDays > (currentUser.totalAllowanceTimeOffInYear - currentUser.tookAllowanceTimeOff) ) 
        {
            errors.push("Reduce count of took days");
        }

        let note = document.getElementById("time-off-note") as HTMLInputElement;

        if (note.value && note.value.length > 400) {
            errors.push("Too much for note");
        }

        let startDateParsed = new Date(startDate.value);
        let endDateParsed = new Date(endDate.value);

        if (endDateParsed < startDateParsed) {
            errors.push("End date cannot be prior start date");
        }

        const isDatesEqual = (first:Date, second:Date) => {
            return first.getFullYear() == second.getFullYear() &&
                    first.getMonth() == second.getMonth() && first.getDate() == second.getDate();
        };

        if (isDatesEqual(startDateParsed, endDateParsed)) {
            let startTime = document.getElementById("start-time-off") as HTMLInputElement;
            let endTime = document.getElementById("end-time-off") as HTMLInputElement;

            if (!startTime.value) {
                errors.push("Start time cannot be empty if you selected the same start and end days");
            }

            if (!endTime.value) {
                errors.push("End time cannot be empty if you selected the same start and end days");
            }

            let parsedStartTime = new Date(startTime.value);
            let parsedEndTime = new Date(endTime.value);

            const isEndTimeBeforeStart = () => {
                if (parsedStartTime.getHours() < parsedEndTime.getHours()) {
                    return true;
                }
                if (parsedStartTime.getHours() == parsedEndTime.getHours() && (parsedStartTime.getMinutes() > parsedEndTime.getMinutes())) 
                {
                    return true;
                }
            };

            if (isEndTimeBeforeStart()) {
                errors.push("End time cannot be prior start time");
            }

        }

        if (errors.length) {
            setShowErrors(true);
            setValidationErrors(errors);
            return;
        }

        onSubmit();
    };

    const onEndDate = (value: Dayjs | null, cxt: any) => {
        const milisecondsByDay = 86400000;
        if (value) {
            let start = new Date((document.getElementById("start-date-off") as HTMLInputElement).value);
            let end = value.toDate();

            if (start.getFullYear() == end.getFullYear() && start.getMonth() == end.getMonth() 
                && start.getDate() == end.getDate()) {
                    setTookDays(1);
                    return;
            }

            if (end < start) {
                setTookDays(0);
                return;
            }

            let diff = start - end;

            let took = Math.abs(diff) / milisecondsByDay;

            setTookDays(took+1);
        }
    };

    const onClose = () => {
        setTookDays(0);
        closeTimeOff();
    };

    return (<>
            <Dialog
                    open={show}
                    onClose={onClose}
                    aria-labelledby="responsive-dialog-title"
                >
                <DialogTitle id="responsive-dialog-title">
                    <span style={{ padding: "20px" }} className='flex-column'>
                    <span className='bold'>{currentUser.firstName + " " + currentUser.lastName} 
                        <AccountCircleIcon style={{ marginLeft: "15px" }}/></span> 
                    </span>
                </DialogTitle>
                <form className='flex-column sign-in-controls-column' style={{ margin: "0px 40px 40px 40px" }}>
                    <div>
                        <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
                            <InputLabel style={{ color: "black"}} id="team-select-label">Request type </InputLabel>
                                <NativeSelect
                                defaultValue={TimeOffType.Vacation}
                                inputProps={{
                                    name: 'request-type',
                                    id: 'request-select-type',
                                }}
                            >
                                <option key={TimeOffType.Vacation}
                                        value={TimeOffType.Vacation}>Vacation
                                </option>
                                <option key={TimeOffType.SickLeave}
                                        value={TimeOffType.SickLeave}>Sick Leave
                                </option>
                            </NativeSelect>
                        </Box>
                    </div>
                    <div>
                        <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
                            <div className="flex-row">
                                <Box sx={{ marginTop: "10px", marginBottom: "10px", marginRight:"20px" }}>
                                    <InputLabel style={{ color: "black"}} id="team-select-label">Start date </InputLabel>
                                    <LocalizationProvider dateAdapter={AdapterDayjs}>
                                        <DatePicker value={dayjs(new Date(current.getFullYear(), +selectedMonth.current, +selectedDay.current))} 
                                            slotProps={{
                                                textField: {
                                                  required: true,
                                                  id: 'start-date-off',
                                                },
                                              }} />
                                    </LocalizationProvider>
                                </Box>
                                <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
                                    <InputLabel style={{ color: "black"}} id="team-select-label">Start time </InputLabel>
                                    <LocalizationProvider dateAdapter={AdapterDayjs}>
                                        <TimePicker value={dayjs(new Date(2000, 1, 1, current.getHours(), current.getMinutes(),
                                            current.getSeconds() ))} 
                                            slotProps={{
                                                textField: {
                                                  required: true,
                                                  id: 'start-time-off',
                                                },
                                              }} 
                                         />
                                    </LocalizationProvider>
                                </Box>
                            </div>
                        </Box>
                        <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
                            <div className="flex-row">
                            <Box sx={{ marginTop: "10px", marginBottom: "10px", marginRight:"20px" }}>
                                <InputLabel style={{ color: "black"}} id="team-select-label">End date </InputLabel>
                                <LocalizationProvider dateAdapter={AdapterDayjs}>
                                    <DatePicker onChange={onEndDate} slotProps={{
                                                textField: {
                                                  required: true,
                                                  id: 'end-date-off',
                                                },
                                              }}  />
                                </LocalizationProvider>
                            </Box>
                            <Box sx={{ marginTop: "10px", marginBottom: "10px" }}>
                                <InputLabel style={{ color: "black"}} id="team-select-label">End time </InputLabel>
                                <LocalizationProvider dateAdapter={AdapterDayjs}>
                                    <TimePicker slotProps={{
                                                textField: {
                                                  required: true,
                                                  id: 'end-time-off',
                                                },
                                              }} />
                                </LocalizationProvider>
                            </Box>
                            </div>
                        </Box>
                        <Box sx={{ marginTop: "10px", marginBottom: "50px" }}>
                            <InputLabel style={{ color: "black"}} id="team-select-label">Request note </InputLabel>
                            <TextareaAutosize id="time-off-note" minRows={3} maxRows={4} aria-label="Note" placeholder="" />
                        </Box>
                        <p>Available total days to take: {currentUser.totalAllowanceTimeOffInYear - currentUser.tookAllowanceTimeOff}</p>
                        <TookDays/>
                        <ValidationErrors/>
                    </div>
                </form>
                <DialogActions className='flex-row-center'>
                    <Button onClick={sumbit} autoFocus>
                        <span>Send Request</span>
                    </Button>
                </DialogActions>
            </Dialog>
    </>);
};

export default memo(RequestTimeOffDialog);