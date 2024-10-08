import SvgIcon, { SvgIconProps } from '@mui/material/SvgIcon';
import Button from '@mui/material/Button';
import { Link } from '@mui/material';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import axios, { AxiosResponse } from 'axios';
import DialogTitle from '@mui/material/DialogTitle';
import TextField from '@mui/material/TextField';
import ApartmentIcon from '@mui/icons-material/Apartment';
import AccountBoxIcon from '@mui/icons-material/AccountBox';
import { DemoItem } from '@mui/x-date-pickers/internals/demo'
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { useState } from 'react';
import { SignInResult } from "../../models/sign-in-result";
import { useNavigate  } from "react-router-dom";
import { ApplciationSettings } from '../../models/application-settings';
import { SignUpResult } from '../../models/sign-up-result';

function LandingNavbar() {

  const [openLogin, setOpenLogin] = useState(false);
  const [openSignUp, setOpenSignUp] = useState(false);
  const [showErrors, setShowErrors] = useState(false);
  const [validationErrors, setValidationErrors] = useState([""]);
  const navigateTo = useNavigate();

  const handleClickOpen = () => {
    setOpenLogin(true);
  };

  return (<>
      <span className='flex-row-between'>
          <HomeIcon color="primary" />
          <Button size="large" onClick={handleClickOpen} color="primary" variant="text">Sign in</Button>
          <SignInDialog/>
          <SignUpDialog/>
      </span>
  </>);


  function HomeIcon(props: SvgIconProps) {
      return (
        <Link href="/">
          <SvgIcon fontSize="large" {...props}>
          <path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" />
        </SvgIcon>
        </Link>
      );
  }

  function SignInDialog() {
    const handleCloseLogin = () => {
      setOpenLogin(false);
      validationErrors.splice(0, validationErrors.length)
      setValidationErrors(validationErrors);
      setShowErrors(false);
    };

    const handleDialogClickSignUp = () => {
      setOpenLogin(false);
      validationErrors.splice(0, validationErrors.length)
      setValidationErrors(validationErrors);
      setShowErrors(false);
      setOpenSignUp(true);
    };
    const handleLogin = () => {

      const email = document.getElementById("email") as HTMLInputElement;
      const password = document.getElementById("password") as HTMLInputElement;
      validationErrors.splice(0, validationErrors.length)
      setValidationErrors(validationErrors);
      setShowErrors(false);
      let errors = [];

      if (!email?.value) {
        errors.push("Email is requried");
        setValidationErrors(errors);
      }

      if (!password?.value) {
        errors.push("Password is requried");
        setValidationErrors(errors);
      }

      if (errors.filter(x => x != "").length > 0) {
        setShowErrors(true);
        return;
      }

      axios.post(`${ApplciationSettings.webApiUrl()}/account/login-to-company-workspace`, {
        email: email.value,
        password: password.value
      },
      {}
      )
      .then(function (response: AxiosResponse<SignInResult>) {
          if (!response.data.success) {
            setShowErrors(true);
            validationErrors.push(response.data.message);
            setValidationErrors(validationErrors);
          } else {
            localStorage.setItem("ACCESS_TOKEN", response.data.token.accessToken);
            localStorage.setItem("REFRESH_ACCESS_TOKEN", response.data.token.refreshToken);
            navigateTo("/workspace");
          }
      })
      .catch(function (error) {
        console.log(error);
      });
    };
    return (<Dialog
        open={openLogin}
        onClose={handleCloseLogin}
        aria-labelledby="responsive-dialog-title"
      >
        <DialogTitle id="responsive-dialog-title">
            <span style={{ padding: "20px" }} className='flex-column'>
              <ValidationErrors/>
              <span className='bold'>Sign In</span> 
              <small className='small-xs'>Login to enter to your companies workspace. <ApartmentIcon/></small>
            </span>
        </DialogTitle>
        <form className='flex-column sign-in-controls-column' style={{ margin: "0px 40px 40px 40px" }}>
          <TextField
              required
              autoComplete='email'
              id="email"
              className='form-sign-on-control'
              label="Email"
              defaultValue=""
              variant="standard"
            />
          <TextField
              required
              label="Password"
              id="password"
              className='form-sign-on-control'
              autoComplete='current-password'
              type="password"
              defaultValue=""
              variant="standard"
            />
            <a id="forgot-password-btn" className='bold small-xs'>Forgot Password?</a>
        </form>
        <DialogActions className='flex-row-center'>
          <Button autoFocus onClick={handleLogin}>
            <span>Sign IN</span>
          </Button>
        </DialogActions>
        <DialogActions className='flex-row-center'>
            <span>Don't have an account? <Button autoFocus onClick={handleDialogClickSignUp}>
            <span>Sign Up</span>
          </Button></span>
        </DialogActions>
      </Dialog>);
  }


  function SignUpDialog() {

    const handleCloseSignUp = () => {
      setOpenSignUp(false);
    };

    const handleAlreadyHaveAccount = () => {
      setOpenLogin(true);
      setOpenSignUp(false);
    };

    const handleSignUp = () => {
      const email = document.getElementById("email") as HTMLInputElement;
      const password = document.getElementById("password") as HTMLInputElement;
      const fName = document.getElementById("first-name") as HTMLInputElement;
      const lName = document.getElementById("last-name") as HTMLInputElement;
      const birthDate = document.getElementById("birth-date") as HTMLInputElement;
      const jobTitle = document.getElementById("job-title") as HTMLInputElement;
      setValidationErrors([""]);
      setShowErrors(false);

      if (!email?.value) {
        validationErrors.push("Email is requried");
        setValidationErrors(validationErrors);
      }

      if (!password?.value) {
        validationErrors.push("Password is requried");
        setValidationErrors(validationErrors);
      }

      if (!fName?.value) {
        validationErrors.push("First Name is requried");
        setValidationErrors(validationErrors);
      }

      if (!lName?.value) {
        validationErrors.push("Last Name is requried");
        setValidationErrors(validationErrors);
      }

      if (validationErrors.filter(x => x != "").length > 0) {
        setShowErrors(true);
        return;
      }

      axios.post(`${ApplciationSettings.webApiUrl()}/account/sign-up`, {
        email: email.value,
        password: password.value,
        firstName: fName.value,
        lastName: lName.value,
        birthDate: new Date(birthDate.value),
        jobTitle: jobTitle.value
      },
      {}
      )
      .then(function (response: AxiosResponse<SignUpResult>) {
          if (!response.data.success) {
            setShowErrors(true);
            validationErrors.push(response.data.message);
            setValidationErrors(validationErrors);
          } 
          else 
          {
            localStorage.setItem("ACCESS_TOKEN", response.data.token.accessToken);
            localStorage.setItem("REFRESH_ACCESS_TOKEN", response.data.token.refreshToken);
            navigateTo("/workspace");
          }
      })
      .catch(function (error) {
        console.log(error);
      });
    };

    return (<Dialog
      open={openSignUp}
      className="sign-up-dialog"
      fullWidth={true}
      onClose={handleCloseSignUp}
      aria-labelledby="responsive-dialog-title"
    >
      <DialogTitle id="responsive-dialog-title">
        <span style={{ padding: "20px" }} className='flex-column'>
          <ValidationErrors/>
          <span className='bold'>Sign Up</span> 
          <small className='small-xs'>Sign up to create your company <AccountBoxIcon/></small>
        </span>
      </DialogTitle>
        <form className='flex-column sign-in-controls-column' style={{ margin: "0px 40px 40px 40px" }}>
          <TextField
              required
              id="email"
              autoComplete='email'
              className='form-sign-on-control'
              label="Email"
              defaultValue=""
              variant="standard"
            />
          <TextField
              required
              id="password"
              label="Password"
              className='form-sign-on-control'
              autoComplete='current-password'
              type="password"
              defaultValue=""
              variant="standard"
            />
          <TextField
              required
              id="first-name"
              autoComplete='first-name'
              className='form-sign-on-control'
              label="First Name"
              defaultValue=""
              variant="standard"
          />
          <TextField
              required
              id="last-name"
              autoComplete='last-name'
              className='form-sign-on-control'
              label="Last Name"
              defaultValue=""
              variant="standard"
          />
          <span className='form-sign-on-control'>
            <LocalizationProvider dateAdapter={AdapterDayjs}>
              <DemoItem label="Birth Date">
                  <DatePicker slotProps={{
                    textField: {
                      id: 'birth-date',
                    },
                  }} />
              </DemoItem>
            </LocalizationProvider>
          </span>
          <TextField
              label="Job Title"
              id="job-title"
              className='form-sign-on-control'
              autoComplete='job-title'
              defaultValue=""
              variant="standard"
            />
        </form>
        <DialogActions className='flex-row-center'>
          <Button autoFocus onClick={handleSignUp}>
            <span>Sign UP</span>
          </Button>
        </DialogActions>
        <DialogActions className='flex-row-center'>
            <span>Already have an account? <Button autoFocus onClick={handleAlreadyHaveAccount}>
            <span>Sign In</span>
          </Button></span>
        </DialogActions>
      </Dialog>);
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

}



export default LandingNavbar;