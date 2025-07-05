from enum import Enum
from datetime import datetime
from app.extensions import db


class UserRole(Enum):
    INVESTOR = 'investor'
    LANDBUYER = 'landbuyer'
    ADMIN = 'admin'


class LandStatus(Enum):
    AVAILABLE = 'Available'
    SOLD = 'Sold'
    RESERVED = 'Reserved'
    PENDING_VERIFICATION = 'Pending Verification'


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(
        db.Enum(
            UserRole,
            values_callable=lambda x: [e.value for e in x],
            native_enum=False,
            create_type=False
        ),
        default=UserRole.INVESTOR,
        nullable=False
    )
    id_number = db.Column(db.String(50), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    next_of_kin_name = db.Column(db.String(100), nullable=True)
    next_of_kin_phone = db.Column(db.String(20), nullable=True)
    profile_pic = db.Column(db.String(200), nullable=True)
    firebase_uid = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    investments = db.relationship(
        'Investment',
        backref='investor',
        lazy=True,
        cascade='all, delete-orphan'
    )
    transactions = db.relationship(
        'Transaction',
        backref='user_rel',
        lazy=True,
        cascade='all, delete-orphan'
    )
    land_purchases = db.relationship(
        'LandPurchase',
        backref='buyer',
        lazy=True,
        cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<User {self.email} ({self.role.value})>'


class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    tier = db.Column(db.String(50), nullable=False)
    purpose = db.Column(db.String(200), nullable=True)
    date_invested = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    target_amount = db.Column(db.Float, nullable=True)

    transactions = db.relationship(
        'Transaction',
        backref='investment_rel',
        lazy=True
    )

    def __repr__(self):
        return f'<Investment {self.id} by User ID {self.user_id}>'


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    investment_id = db.Column(db.Integer, db.ForeignKey('investment.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='PENDING', nullable=False)
    mpesa_receipt_number = db.Column(db.String(100), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    merchant_request_id = db.Column(db.String(100), unique=True, nullable=True)
    checkout_request_id = db.Column(db.String(100), unique=True, nullable=True)

    def __repr__(self):
        return f'<Transaction {self.id} - {self.status}>'


class Land(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plot_reference = db.Column(db.String(100), unique=True, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    size_acres = db.Column(db.Float, nullable=False)
    price_kes = db.Column(db.Float, nullable=False)
    status = db.Column(
        db.Enum(
            LandStatus,
            values_callable=lambda x: [e.value for e in x],
            native_enum=False,
            create_type=False
        ),
        default=LandStatus.AVAILABLE,
        nullable=False
    )
    description = db.Column(db.Text, nullable=True)
    added_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    image_filename = db.Column(db.String(255), nullable=True)

    land_purchases = db.relationship(
        'LandPurchase',
        backref='land_bought',
        lazy=True,
        cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<Land {self.plot_reference} at {self.location}>'


class LandPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    land_id = db.Column(db.Integer, db.ForeignKey('land.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    amount_paid = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<LandPurchase {self.id} (User: {self.user_id}, Land: {self.land_id})>'


class UserModel:
    def __init__(
        self,
        full_name,
        email,
        password,
        role=UserRole.INVESTOR,
        id_number=None,
        phone_number=None,
        next_of_kin_name=None,
        next_of_kin_phone=None,
        profile_pic=None,
        firebase_uid=None
    ):
        self.full_name = full_name
        self.email = email
        self.password = password
        self.role = role
        self.id_number = id_number
        self.phone_number = phone_number
        self.next_of_kin_name = next_of_kin_name
        self.next_of_kin_phone = next_of_kin_phone
        self.profile_pic = profile_pic
        self.firebase_uid = firebase_uid
