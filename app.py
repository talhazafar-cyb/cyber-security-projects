from flask import Flask, render_template, request, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyber.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# DATABASE MODEL

class Report(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    threat_type = db.Column(db.String(100))

    severity = db.Column(db.String(50))

    location = db.Column(db.String(200))

    detection_method = db.Column(db.String(100))

    description = db.Column(db.Text)

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

# HOME PAGE

@app.route('/')
def home():

    reports = Report.query.order_by(
        Report.id.desc()
    ).all()

    # COUNTS

    total = Report.query.count()

    high = Report.query.filter_by(
        severity='High'
    ).count()

    manual = Report.query.filter_by(
        detection_method='Manual'
    ).count()

    auto = Report.query.filter_by(
        detection_method='Automatic'
    ).count()

    # RECENT ALERTS

    recent_alerts = Report.query.order_by(
        Report.timestamp.desc()
    ).limit(5).all()

    return render_template(

        'index.html',

        total=total,

        high=high,

        manual=manual,

        auto=auto,

        recent_alerts=recent_alerts

    )

# DASHBOARD

@app.route('/dashboard')
def dashboard():

    reports = Report.query.order_by(
        Report.timestamp.desc()
    ).all()

    total = Report.query.count()

    dos = Report.query.filter_by(
        threat_type='DoS Attack'
    ).count()

    portscan = Report.query.filter_by(
        threat_type='Port Scan'
    ).count()

    phishing = Report.query.filter_by(
        threat_type='Phishing'
    ).count()

    spam = Report.query.filter_by(
        threat_type='Spam'
    ).count()

    auto = Report.query.filter_by(
        detection_method='Automatic'
    ).count()

    manual = Report.query.filter_by(
        detection_method='Manual'
    ).count()

    return render_template(

        'dashboard.html',

        reports=reports,

        total=total,

        dos=dos,

        portscan=portscan,

        phishing=phishing,

        spam=spam,

        auto=auto,

        manual=manual

    )

# REPORTS PAGE

@app.route('/reports', methods=['GET', 'POST'])
def reports():

    if request.method == 'POST':

        new_report = Report(

            threat_type=request.form['threat'],

            severity=request.form['severity'],

            location=request.form['location'],

            detection_method=request.form['method'],

            description=request.form['description']

        )

        db.session.add(new_report)

        db.session.commit()

        return redirect('/reports')

    all_reports = Report.query.order_by(
        Report.id.desc()
    ).all()

    return render_template(
        'reports.html',
        reports=all_reports
    )

# API FOR UBUNTU DETECTOR

@app.route('/api/report', methods=['POST'])
def api_report():

    try:

        data = request.get_json()

        new_report = Report(

            threat_type=data['threat_type'],

            location=data['location'],

            severity=data['severity'],

            detection_method=data['detection_method']

        )

        db.session.add(new_report)

        db.session.commit()

        return jsonify({

            "message": "Threat Report Added"

        }), 200

    except Exception as e:

        return jsonify({

            "error": str(e)

        }), 500

# DELETE REPORT

@app.route('/delete/<int:id>')
def delete(id):

    report = Report.query.get_or_404(id)

    db.session.delete(report)

    db.session.commit()

    return redirect('/reports')

# ANALYTICS

@app.route('/analytics')
def analytics():

    total = Report.query.count()

    high = Report.query.filter_by(
        severity='High'
    ).count()

    medium = Report.query.filter_by(
        severity='Medium'
    ).count()

    low = Report.query.filter_by(
        severity='Low'
    ).count()

    dos = Report.query.filter_by(
        threat_type='DoS Attack'
    ).count()

    portscan = Report.query.filter_by(
        threat_type='Port Scan'
    ).count()

    phishing = Report.query.filter_by(
        threat_type='Phishing'
    ).count()

    spam = Report.query.filter_by(
        threat_type='Spam'
    ).count()

    manual = Report.query.filter_by(
        detection_method='Manual'
    ).count()

    auto = Report.query.filter_by(
        detection_method='Automatic'
    ).count()

    return render_template(

        'analytics.html',

        total=total,

        high=high,

        medium=medium,

        low=low,

        dos=dos,

        portscan=portscan,

        phishing=phishing,

        spam=spam,

        manual=manual,

        auto=auto

    )

# ACCURACY

@app.route('/accuracy')
def accuracy():

    return render_template('accuracy.html')

# RUN
@app.route('/live-data')
def live_data():

    reports = Report.query.order_by(
        Report.timestamp.desc()
    ).limit(5).all()

    total = Report.query.count()

    high = Report.query.filter_by(
        severity='High'
    ).count()

    manual = Report.query.filter_by(
        detection_method='Manual'
    ).count()

    auto = Report.query.filter_by(
        detection_method='Automatic'
    ).count()

    data = {

        "total": total,

        "high": high,

        "manual": manual,

        "auto": auto,

        "reports": [

            {

                "threat_type": report.threat_type,

                "severity": report.severity,

                "detection_method":
                report.detection_method,

                "timestamp":
                str(report.timestamp)

            }

            for report in reports

        ]

    }

    return jsonify(data)
if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )