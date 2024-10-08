import LandingNavbar from "./landing-navbar";
import './landing-main.css'
import LandingFooter from "./landing-footer";
import Button from '@mui/material/Button';
import { useState } from "react";

function LandingMain() {

    const [openLogin, setOpenLogin] = useState(false);

    const handleClickOpen = () => {
      setOpenLogin(true);
    };

    return (<>
      <header className="landing-navbar">
        <LandingNavbar/>
      </header>
      <main className="landing-main flex-row-center">
          <section>
            {/* <Button size="large" color="primary" variant="text">Get Started</Button> */}
            <h4 style={{color:"black"}}>Click "Sign In" to start</h4>
          </section>
      </main>
      <footer className="landing-footer">
        <LandingFooter/>
      </footer>
    </>);
}

export default LandingMain;