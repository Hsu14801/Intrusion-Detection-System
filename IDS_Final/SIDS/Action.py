from enum import Enum

class Action(Enum):
    # An action to be done for detection

    ALERT = 1
    PASS = 2

    def action(istr):
        #Retrun an action corresponding to the string
        action = istr.lower().strip()
        try:
            
            if(action == "alert"):
                return Action.ALERT
            if(action == "pass"):
                return Action.PASS
  

        except ValueError as e:
            
            print("Invalid rule for incorrect action : {e}")


        
