from rocketry import Rocketry
import cisa_alerts 

app = Rocketry()

@app.task('every 3 hour')
def do_hourly():
    cisa_alerts.main() # execute script

@app.task('every 1 day')
def do_daily():
    cisa_alerts.reset_db() # clear db.txt

if __name__ == "__main__":
    app.run()
