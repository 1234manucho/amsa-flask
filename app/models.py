# functions/app/models.py (assuming this is in functions/app/models.py)

from enum import Enum
from datetime import datetime

# IMPORTANT: This import assumes 'db' is defined and initialized in app/__init__.py
# as part of the Flask application factory pattern.
# Do NOT run this file directly. It should be imported by __init__.py or other app modules.
from app.extensions import db

# No need to import generate_password_hash or check_password_hash here
# unless you specifically use them outside of the User model methods.
# from werkzeug.security import generate_password_hash, check_password_hash # Removed, as not directly used at module level


class UserRole(Enum):
    """
    Defines the roles a user can have in the system.
    The string values ('investor', 'landbuyer', 'admin') are what get stored in the database.
    """
    INVESTOR = 'investor'
    LANDBUYER = 'landbuyer'
    ADMIN = 'admin'

# Optional: You could define an Enum for Land Status for better type safety
class LandStatus(Enum):
    AVAILABLE = 'Available'
    SOLD = 'Sold'
    RESERVED = 'Reserved'
    PENDING_VERIFICATION = 'Pending Verification' # Example of another status

class User(db.Model):
    """
    Represents a user in the system, mapped to the 'user' table in the database.
    """
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Hashed password

    # Using db.Enum with values_callable to ensure proper mapping of string values
    # from/to the database. native_enum=False for better compatibility with SQLite.
    # create_type=False is often added for SQLAlchemy 2.0+ and migrations with enums
    # when you want to manage the enum type in the DB yourself or just store strings.
    role = db.Column(db.Enum(UserRole, values_callable=lambda x: [e.value for e in x],
                             native_enum=False, create_type=False),
                     default=UserRole.INVESTOR, nullable=False)

    id_number = db.Column(db.String(50), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    next_of_kin_name = db.Column(db.String(100), nullable=True)
    next_of_kin_phone = db.Column(db.String(20), nullable=True)
    profile_pic = db.Column(db.String(200), nullable=True) # Storing filename or URL
    firebase_uid = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships:
    # investments: A user can have many investments.
    # transactions: A user can have many transactions.
    # land_purchases: A user can make many land purchases.
    # lands_owned: (Optional) If users can 'list' or 'own' lands for sale.
    investments = db.relationship('Investment', backref='investor', lazy=True, cascade='all, delete-orphan')
    transactions = db.relationship('Transaction', backref='user_rel', lazy=True, cascade='all, delete-orphan')
    land_purchases = db.relationship('LandPurchase', backref='buyer', lazy=True, cascade='all, delete-orphan')
    # If a user can 'own' or 'add' land listings, uncomment and adjust:
    # lands_listed = db.relationship('Land', backref='lister', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.email} ({self.role.value})>'

    # Password hashing and checking methods should be in the model
    # from werkzeug.security import generate_password_hash, check_password_hash
    # You might want to import these directly within the methods if they are only used here.
    # Or, import them at the top of this file if used by other methods.
    # For now, assuming they are imported where set_password/check_password_hash are called.

class Investment(db.Model):
    """
    Represents an investment made by a user.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    tier = db.Column(db.String(50), nullable=False) # e.g., 'Bronze', 'Silver', 'Gold'
    purpose = db.Column(db.String(200), nullable=True)
    date_invested = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    target_amount = db.Column(db.Float, nullable=True) # For specific investment goals

    # Relationship to transactions related to this investment
    # A single investment can be tied to multiple transactions (e.g., installments)
    transactions = db.relationship('Transaction', backref='investment_rel', lazy=True)

    def __repr__(self):
        # Ensure investor is loaded if you access investor.email outside of a query that loads it
        return f'<Investment {self.id} by User ID {self.user_id}>'

class Transaction(db.Model):
    """
    Represents a financial transaction, either for investments or other purposes.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    investment_id = db.Column(db.Integer, db.ForeignKey('investment.id'), nullable=True) # Optional link to an investment
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='PENDING', nullable=False) # e.g., 'PENDING', 'COMPLETED', 'FAILED'
    mpesa_receipt_number = db.Column(db.String(100), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), nullable=True) # Phone number associated with the transaction
    merchant_request_id = db.Column(db.String(100), unique=True, nullable=True) # For MPESA C2B/STK push
    checkout_request_id = db.Column(db.String(100), unique=True, nullable=True) # For MPESA STK push

    def __repr__(self):
        return f'<Transaction {self.id} - {self.status}>'

class Land(db.Model):
    """
    Represents a parcel of land available for purchase.
    """
    id = db.Column(db.Integer, primary_key=True)
    plot_reference = db.Column(db.String(100), unique=True, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    size_acres = db.Column(db.Float, nullable=False)
    price_kes = db.Column(db.Float, nullable=False)
    # Using an Enum for status for consistency (optional, but good practice)
    status = db.Column(db.Enum(LandStatus, values_callable=lambda x: [e.value for e in x],
                               native_enum=False, create_type=False),
                       default=LandStatus.AVAILABLE, nullable=False)
    description = db.Column(db.Text, nullable=True)
    added_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    image_filename = db.Column(db.String(255), nullable=True) # Storing filename or URL

    # If a user 'lists' this land, link to the User model. Uncomment if applicable.
    # lister_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationship to land purchases (backref 'land_bought' defined on LandPurchase)
    # You can also explicitly define it here if you prefer:
    land_purchases = db.relationship('LandPurchase', backref='land_bought', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Land {self.plot_reference} at {self.location}>'

class LandPurchase(db.Model):
    """
    Records a purchase of land by a user.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    land_id = db.Column(db.Integer, db.ForeignKey('land.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    amount_paid = db.Column(db.Float, nullable=False)

    # Relationships:
    # The backrefs 'buyer' (on User) and 'land_bought' (on Land) are set in their respective models.
    # No need to duplicate db.relationship calls here.
    # user = db.relationship('User', backref='land_purchases', lazy=True) # Redundant
    # land = db.relationship('Land', backref='purchases', lazy=True) # Redundant

    def __repr__(self):
        return f'<LandPurchase {self.id} (User: {self.user_id}, Land: {self.land_id})>'


# --- UserModel (Kept as per your request, with reinforced notes) ---
# IMPORTANT: This class DOES NOT inherit from db.Model.
# Therefore, it CANNOT be used with db.session.add(), .query, or other SQLAlchemy ORM methods
# for direct database persistence.
# Its purpose must be for something else, e.g., a data transfer object (DTO),
# a form validation object (e.g., with WTForms), or an in-memory representation that is later converted
# to a 'User' (db.Model) instance for database operations.
class UserModel:
    def __init__(self, full_name, email, password, role=UserRole.INVESTOR, id_number=None, phone_number=None,
                 next_of_kin_name=None, next_of_kin_phone=None, profile_pic=None, firebase_uid=None):
        self.full_name = full_name
        self.email = email
        self.password = password # This should be a HASHED password if creating a UserModel from a form
        self.role = role
        self.id_number = id_number
        self.phone_number = phone_number
        self.next_of_kin_name = next_of_kin_name
        self.next_of_kin_phone = next_of_kin_phone
        self.profile_pic = profile_pic
        self.firebase_uid = firebase_uid
        # self.userId is not an inherent property of UserModel.
        # If this DTO represents an existing user, its ID would be passed in or set after creation.

    # Removed the 'save' method because this class does not interact with the database directly.
    # If you need to save a UserModel, you must convert its data into a User (db.Model) instance first.
    # Example conversion:
    # def to_db_model(self):
    #     from werkzeug.security import generate_password_hash # Import here if only used for this conversion
    #     return User(
    #         full_name=self.full_name,
    #         email=self.email,
    #         password=generate_password_hash(self.password), # Hash if it's plaintext here
    #         role=self.role,
    #         id_number=self.id_number,
    #         # ... other fields
    #     )