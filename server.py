from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
import os
import logging
from pathlib import Path
import uuid
import bcrypt
import jwt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment
import base64
import io

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import certifi
ca = certifi.where()

mongo_url = os.environ["MONGO_URL"]

client = AsyncIOMotorClient(
    mongo_url,
    tls=True,
    tlsCAFile=ca
)

db = client[os.environ["DB_NAME"]]

# JWT Settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production-KKK-RiceTracker-2025')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(days=7)

security = HTTPBearer()

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ===== MODELS =====

class Admin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    name: str = "Admin"
    phone: str = ""
    email: str = ""
    force_password_change: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    sku: str = Field(default_factory=lambda: f"SKU-{uuid.uuid4().hex[:8].upper()}")
    category: str = ""
    price_per_kg: float
    purchase_cost_per_kg: float
    available_stock_kg: float = 0.0
    image_url: str = ""
    description: str = ""
    low_stock_threshold: float = 10.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StockHistory(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    product_id: str
    product_name: str
    type: str  # IN or OUT
    quantity_kg: float
    source: str  # purchase, sale, adjust
    reference_id: str = ""  # sale_id or invoice_no
    supplier_id: str = ""
    purchase_cost_per_kg: float = 0.0
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Sale(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    product_id: str
    product_name: str
    quantity_kg: float
    rate_per_kg: float
    total: float
    payment_type: str = "Cash"  # Cash, UPI
    customer_name: str = ""
    notes: str = ""
    sale_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Expense(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    amount: float
    category: str = "General"
    expense_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Supplier(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    phone: str = ""
    items_supplied: str = ""
    total_purchase: float = 0.0
    payment_pending: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ActivityLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str
    user: str = "admin"
    object_type: str
    object_id: str
    old_value: str = ""
    new_value: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ===== INPUT MODELS =====

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class ProductCreate(BaseModel):
    name: str
    category: str = ""
    price_per_kg: float
    purchase_cost_per_kg: float
    available_stock_kg: float = 0.0
    image_url: str = ""
    description: str = ""
    low_stock_threshold: float = 10.0

class StockInRequest(BaseModel):
    product_id: str
    quantity_kg: float
    purchase_cost_per_kg: float
    supplier_id: str = ""
    invoice_ref: str = ""
    notes: str = ""

class SaleCreate(BaseModel):
    product_id: str
    quantity_kg: float
    rate_per_kg: float
    payment_type: str = "Cash"
    customer_name: str = ""
    notes: str = ""

class ExpenseCreate(BaseModel):
    title: str
    amount: float
    category: str = "General"
    notes: str = ""

class SupplierCreate(BaseModel):
    name: str
    phone: str = ""
    items_supplied: str = ""

# ===== HELPER FUNCTIONS =====

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + JWT_EXPIRATION_DELTA
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload['user_id']
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_id = verify_token(credentials.credentials)
    admin = await db.admins.find_one({"id": user_id}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=401, detail="User not found")
    return Admin(**admin)

async def log_activity(action_type: str, object_type: str, object_id: str, old_value: str = "", new_value: str = ""):
    log = ActivityLog(
        action_type=action_type,
        object_type=object_type,
        object_id=object_id,
        old_value=old_value,
        new_value=new_value
    )
    doc = log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.activity_logs.insert_one(doc)

# ===== SEED DEMO DATA =====

@api_router.post("/seed-demo-data")
async def seed_demo_data():
    # Check if already seeded
    existing_admin = await db.admins.find_one({"username": "0987654321"})
    if existing_admin:
        return {"message": "Demo data already exists"}
    
    # Create demo admin
    admin = Admin(
        username="0987654321",
        password_hash=hash_password("1234"),
        name="Shop Owner",
        phone="0987654321",
        force_password_change=True
    )
    admin_doc = admin.model_dump()
    admin_doc['created_at'] = admin_doc['created_at'].isoformat()
    await db.admins.insert_one(admin_doc)
    
    # Create 20 demo rice products
    rice_varieties = [
        {"name": "Ponni Raw Rice", "category": "Raw Rice", "price": 45.0, "cost": 38.0, "stock": 500, "img": "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400"},
        {"name": "Ponni Boiled Rice", "category": "Boiled Rice", "price": 48.0, "cost": 40.0, "stock": 450, "img": "https://images.unsplash.com/photo-1516684732162-798a0062be99?w=400"},
        {"name": "Sona Masoori", "category": "Premium", "price": 52.0, "cost": 44.0, "stock": 400, "img": "https://images.unsplash.com/photo-1536304993881-ff6e9eefa2a6?w=400"},
        {"name": "Idly Rice", "category": "Specialty", "price": 50.0, "cost": 42.0, "stock": 300, "img": "https://images.unsplash.com/photo-1628418316455-e6c99f9c3c6e?w=400"},
        {"name": "Seeraga Samba", "category": "Premium", "price": 120.0, "cost": 100.0, "stock": 200, "img": "https://images.unsplash.com/photo-1599909533080-28a8a4c5e596?w=400"},
        {"name": "Rajabogam", "category": "Specialty", "price": 90.0, "cost": 75.0, "stock": 150, "img": "https://images.unsplash.com/photo-1615485290382-441e4d049cb5?w=400"},
        {"name": "IR 20", "category": "Standard", "price": 40.0, "cost": 33.0, "stock": 600, "img": "https://images.unsplash.com/photo-1585776245991-cf89dd7fc73a?w=400"},
        {"name": "IR 36", "category": "Standard", "price": 42.0, "cost": 35.0, "stock": 550, "img": "https://images.unsplash.com/photo-1569876388992-765ba96ca1f1?w=400"},
        {"name": "Basmati Rice", "category": "Premium", "price": 150.0, "cost": 125.0, "stock": 250, "img": "https://images.unsplash.com/photo-1598170845058-32b9d6a5da37?w=400"},
        {"name": "Thanjavur Ponni", "category": "Traditional", "price": 55.0, "cost": 46.0, "stock": 380, "img": "https://images.unsplash.com/photo-1596560548464-f010549b84d7?w=400"},
        {"name": "Kolam Rice", "category": "Standard", "price": 46.0, "cost": 38.0, "stock": 420, "img": "https://images.unsplash.com/photo-1612429085511-4e0b0c9b9a3e?w=400"},
        {"name": "Matta Rice", "category": "Specialty", "price": 65.0, "cost": 54.0, "stock": 280, "img": "https://images.unsplash.com/photo-1563620013-b5d4f4c60668?w=400"},
        {"name": "Kalkandu BPT Rice", "category": "Premium", "price": 75.0, "cost": 62.0, "stock": 220, "img": "https://images.unsplash.com/photo-1536304929831-69f1c0e63888?w=400"},
        {"name": "Mappillai Samba", "category": "Traditional", "price": 110.0, "cost": 92.0, "stock": 180, "img": "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400"},
        {"name": "Kattuyanam Rice", "category": "Traditional", "price": 95.0, "cost": 79.0, "stock": 160, "img": "https://images.unsplash.com/photo-1516684732162-798a0062be99?w=400"},
        {"name": "Bamboo Rice", "category": "Specialty", "price": 200.0, "cost": 170.0, "stock": 100, "img": "https://images.unsplash.com/photo-1536304993881-ff6e9eefa2a6?w=400"},
        {"name": "Brown Rice", "category": "Health", "price": 80.0, "cost": 66.0, "stock": 320, "img": "https://images.unsplash.com/photo-1628418316455-e6c99f9c3c6e?w=400"},
        {"name": "Broken Rice", "category": "Economy", "price": 30.0, "cost": 24.0, "stock": 700, "img": "https://images.unsplash.com/photo-1599909533080-28a8a4c5e596?w=400"},
        {"name": "Steam Rice", "category": "Standard", "price": 44.0, "cost": 36.0, "stock": 480, "img": "https://images.unsplash.com/photo-1615485290382-441e4d049cb5?w=400"},
        {"name": "Jeera Rice Mix", "category": "Premium", "price": 130.0, "cost": 108.0, "stock": 140, "img": "https://images.unsplash.com/photo-1585776245991-cf89dd7fc73a?w=400"}
    ]
    
    for rice in rice_varieties:
        product = Product(
            name=rice["name"],
            category=rice["category"],
            price_per_kg=rice["price"],
            purchase_cost_per_kg=rice["cost"],
            available_stock_kg=rice["stock"],
            image_url=rice["img"],
            description=f"High quality {rice['name']} from trusted suppliers"
        )
        doc = product.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        doc['updated_at'] = doc['updated_at'].isoformat()
        await db.products.insert_one(doc)
    
    return {"message": "Demo data seeded successfully", "admin_username": "0987654321", "admin_password": "1234"}

# ===== AUTH ROUTES =====

@api_router.post("/auth/login")
async def login(req: LoginRequest):
    admin = await db.admins.find_one({"username": req.username}, {"_id": 0})
    if not admin or not verify_password(req.password, admin['password_hash']):
        raise HTTPException(status_code=401, detail="User/pass check pannunga, seri illa na retry pannunga")
    
    token = create_token(admin['id'])
    return {
        "token": token,
        "force_password_change": admin.get('force_password_change', False),
        "user": {
            "id": admin['id'],
            "username": admin['username'],
            "name": admin['name']
        }
    }

@api_router.post("/auth/change-password")
async def change_password(req: ChangePasswordRequest, current_user: Admin = Depends(get_current_user)):
    admin = await db.admins.find_one({"id": current_user.id}, {"_id": 0})
    if not verify_password(req.old_password, admin['password_hash']):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    
    new_hash = hash_password(req.new_password)
    await db.admins.update_one(
        {"id": current_user.id},
        {"$set": {"password_hash": new_hash, "force_password_change": False}}
    )
    
    await log_activity("password_changed", "admin", current_user.id)
    return {"message": "Password changed successfully"}

@api_router.get("/auth/me")
async def get_me(current_user: Admin = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "name": current_user.name,
        "phone": current_user.phone,
        "email": current_user.email,
        "force_password_change": current_user.force_password_change
    }

# ===== PRODUCTS ROUTES =====

@api_router.get("/products")
async def get_products(page: int = 1, size: int = 20, search: str = "", low_stock: bool = False, current_user: Admin = Depends(get_current_user)):
    query = {}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"sku": {"$regex": search, "$options": "i"}}
        ]
    if low_stock:
        query["$expr"] = {"$lt": ["$available_stock_kg", "$low_stock_threshold"]}
    
    total = await db.products.count_documents(query)
    products = await db.products.find(query, {"_id": 0}).skip((page - 1) * size).limit(size).to_list(size)
    
    return {"products": products, "total": total, "page": page, "size": size}

@api_router.get("/products/{product_id}")
async def get_product(product_id: str, current_user: Admin = Depends(get_current_user)):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@api_router.post("/products")
async def create_product(product_data: ProductCreate, current_user: Admin = Depends(get_current_user)):
    product = Product(**product_data.model_dump())
    doc = product.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    await db.products.insert_one(doc)
    await log_activity("product_created", "product", product.id, "", product.name)
    return {"message": "Product created", "product": product.model_dump()}

@api_router.put("/products/{product_id}")
async def update_product(product_id: str, product_data: ProductCreate, current_user: Admin = Depends(get_current_user)):
    existing = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = product_data.model_dump()
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    await db.products.update_one({"id": product_id}, {"$set": update_data})
    await log_activity("product_updated", "product", product_id, existing.get('name', ''), update_data.get('name', ''))
    return {"message": "Product updated"}

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, current_user: Admin = Depends(get_current_user)):
    # Check if product is used in sales
    sales_count = await db.sales.count_documents({"product_id": product_id})
    if sales_count > 0:
        raise HTTPException(status_code=400, detail="Cannot delete product with existing sales. Consider soft delete.")
    
    await db.products.delete_one({"id": product_id})
    await log_activity("product_deleted", "product", product_id)
    return {"message": "Product deleted"}

# ===== STOCK ROUTES =====

@api_router.post("/stock/in")
async def add_stock_in(req: StockInRequest, current_user: Admin = Depends(get_current_user)):
    product = await db.products.find_one({"id": req.product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Create stock history
    stock_history = StockHistory(
        product_id=req.product_id,
        product_name=product['name'],
        type="IN",
        quantity_kg=req.quantity_kg,
        source="purchase",
        reference_id=req.invoice_ref,
        supplier_id=req.supplier_id,
        purchase_cost_per_kg=req.purchase_cost_per_kg,
        notes=req.notes
    )
    doc = stock_history.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.stock_history.insert_one(doc)
    
    # Update product stock
    new_stock = product['available_stock_kg'] + req.quantity_kg
    await db.products.update_one(
        {"id": req.product_id},
        {"$set": {"available_stock_kg": new_stock}}
    )
    
    await log_activity("stock_added", "stock", stock_history.id, str(product['available_stock_kg']), str(new_stock))
    return {"message": "Stock added successfully", "new_stock": new_stock}

@api_router.get("/stock/history")
async def get_stock_history(
    page: int = 1,
    size: int = 50,
    product_id: str = "",
    type_filter: str = "",
    from_date: str = "",
    to_date: str = "",
    current_user: Admin = Depends(get_current_user)
):
    query = {}
    if product_id:
        query["product_id"] = product_id
    if type_filter:
        query["type"] = type_filter
    
    total = await db.stock_history.count_documents(query)
    history = await db.stock_history.find(query, {"_id": 0}).sort("created_at", -1).skip((page - 1) * size).limit(size).to_list(size)
    
    return {"history": history, "total": total, "page": page, "size": size}

# ===== SALES ROUTES =====

@api_router.get("/sales")
async def get_sales(
    page: int = 1,
    size: int = 50,
    from_date: str = "",
    to_date: str = "",
    product_id: str = "",
    current_user: Admin = Depends(get_current_user)
):
    query = {}
    if product_id:
        query["product_id"] = product_id
    
    total = await db.sales.count_documents(query)
    sales = await db.sales.find(query, {"_id": 0}).sort("sale_date", -1).skip((page - 1) * size).limit(size).to_list(size)
    
    return {"sales": sales, "total": total, "page": page, "size": size}

@api_router.post("/sales")
async def create_sale(sale_data: SaleCreate, current_user: Admin = Depends(get_current_user)):
    product = await db.products.find_one({"id": sale_data.product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Check stock
    if product['available_stock_kg'] < sale_data.quantity_kg:
        raise HTTPException(
            status_code=400,
            detail=f"Stock theriya matten — innum {product['available_stock_kg']} kg mattum irukku. Continue panna override pannalam?"
        )
    
    # Create sale
    total = sale_data.quantity_kg * sale_data.rate_per_kg
    sale = Sale(
        product_id=sale_data.product_id,
        product_name=product['name'],
        quantity_kg=sale_data.quantity_kg,
        rate_per_kg=sale_data.rate_per_kg,
        total=total,
        payment_type=sale_data.payment_type,
        customer_name=sale_data.customer_name,
        notes=sale_data.notes
    )
    sale_doc = sale.model_dump()
    sale_doc['sale_date'] = sale_doc['sale_date'].isoformat()
    sale_doc['created_at'] = sale_doc['created_at'].isoformat()
    await db.sales.insert_one(sale_doc)
    
    # Create stock history OUT
    stock_history = StockHistory(
        product_id=sale_data.product_id,
        product_name=product['name'],
        type="OUT",
        quantity_kg=sale_data.quantity_kg,
        source="sale",
        reference_id=sale.id,
        notes=f"Sale to {sale_data.customer_name or 'customer'}"
    )
    stock_doc = stock_history.model_dump()
    stock_doc['created_at'] = stock_doc['created_at'].isoformat()
    await db.stock_history.insert_one(stock_doc)
    
    # Update product stock
    new_stock = product['available_stock_kg'] - sale_data.quantity_kg
    await db.products.update_one(
        {"id": sale_data.product_id},
        {"$set": {"available_stock_kg": new_stock}}
    )
    
    await log_activity("sale_created", "sale", sale.id, "", f"{sale_data.quantity_kg}kg of {product['name']}")
    return {"message": "Sale save aachu — stock update ayiduchu", "sale": sale.model_dump()}

@api_router.get("/sales/{sale_id}")
async def get_sale(sale_id: str, current_user: Admin = Depends(get_current_user)):
    sale = await db.sales.find_one({"id": sale_id}, {"_id": 0})
    if not sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    return sale

@api_router.put("/sales/{sale_id}")
async def update_sale(sale_id: str, sale_data: SaleCreate, current_user: Admin = Depends(get_current_user)):
    existing_sale = await db.sales.find_one({"id": sale_id}, {"_id": 0})
    if not existing_sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    
    # Reverse old stock change
    await db.products.update_one(
        {"id": existing_sale['product_id']},
        {"$inc": {"available_stock_kg": existing_sale['quantity_kg']}}
    )
    
    # Check new stock
    product = await db.products.find_one({"id": sale_data.product_id}, {"_id": 0})
    if product['available_stock_kg'] < sale_data.quantity_kg:
        # Restore old stock
        await db.products.update_one(
            {"id": existing_sale['product_id']},
            {"$inc": {"available_stock_kg": -existing_sale['quantity_kg']}}
        )
        raise HTTPException(status_code=400, detail="Insufficient stock for update")
    
    # Apply new stock change
    await db.products.update_one(
        {"id": sale_data.product_id},
        {"$inc": {"available_stock_kg": -sale_data.quantity_kg}}
    )
    
    # Update sale
    total = sale_data.quantity_kg * sale_data.rate_per_kg
    update_data = sale_data.model_dump()
    update_data['total'] = total
    update_data['product_name'] = product['name']
    await db.sales.update_one({"id": sale_id}, {"$set": update_data})
    
    await log_activity("sale_updated", "sale", sale_id)
    return {"message": "Sale updated successfully"}

@api_router.delete("/sales/{sale_id}")
async def delete_sale(sale_id: str, current_user: Admin = Depends(get_current_user)):
    sale = await db.sales.find_one({"id": sale_id}, {"_id": 0})
    if not sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    
    # Restore stock
    await db.products.update_one(
        {"id": sale['product_id']},
        {"$inc": {"available_stock_kg": sale['quantity_kg']}}
    )
    
    # Delete stock history
    await db.stock_history.delete_one({"reference_id": sale_id})
    
    # Delete sale
    await db.sales.delete_one({"id": sale_id})
    
    await log_activity("sale_deleted", "sale", sale_id)
    return {"message": "Sale deleted and stock restored"}

# ===== EXPENSES ROUTES =====

@api_router.get("/expenses")
async def get_expenses(
    page: int = 1,
    size: int = 50,
    category: str = "",
    current_user: Admin = Depends(get_current_user)
):
    query = {}
    if category:
        query["category"] = category
    
    total = await db.expenses.count_documents(query)
    expenses = await db.expenses.find(query, {"_id": 0}).sort("expense_date", -1).skip((page - 1) * size).limit(size).to_list(size)
    
    return {"expenses": expenses, "total": total, "page": page, "size": size}

@api_router.post("/expenses")
async def create_expense(expense_data: ExpenseCreate, current_user: Admin = Depends(get_current_user)):
    expense = Expense(**expense_data.model_dump())
    doc = expense.model_dump()
    doc['expense_date'] = doc['expense_date'].isoformat()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.expenses.insert_one(doc)
    await log_activity("expense_created", "expense", expense.id, "", expense.title)
    return {"message": "Expense added", "expense": expense.model_dump()}

@api_router.put("/expenses/{expense_id}")
async def update_expense(expense_id: str, expense_data: ExpenseCreate, current_user: Admin = Depends(get_current_user)):
    existing = await db.expenses.find_one({"id": expense_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Expense not found")
    
    await db.expenses.update_one({"id": expense_id}, {"$set": expense_data.model_dump()})
    await log_activity("expense_updated", "expense", expense_id)
    return {"message": "Expense updated"}

@api_router.delete("/expenses/{expense_id}")
async def delete_expense(expense_id: str, current_user: Admin = Depends(get_current_user)):
    await db.expenses.delete_one({"id": expense_id})
    await log_activity("expense_deleted", "expense", expense_id)
    return {"message": "Expense deleted"}

# ===== SUPPLIERS ROUTES =====

@api_router.get("/suppliers")
async def get_suppliers(current_user: Admin = Depends(get_current_user)):
    suppliers = await db.suppliers.find({}, {"_id": 0}).to_list(1000)
    return {"suppliers": suppliers}

@api_router.post("/suppliers")
async def create_supplier(supplier_data: SupplierCreate, current_user: Admin = Depends(get_current_user)):
    supplier = Supplier(**supplier_data.model_dump())
    doc = supplier.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.suppliers.insert_one(doc)
    await log_activity("supplier_created", "supplier", supplier.id, "", supplier.name)
    return {"message": "Supplier added", "supplier": supplier.model_dump()}

@api_router.put("/suppliers/{supplier_id}")
async def update_supplier(supplier_id: str, supplier_data: SupplierCreate, current_user: Admin = Depends(get_current_user)):
    await db.suppliers.update_one({"id": supplier_id}, {"$set": supplier_data.model_dump()})
    await log_activity("supplier_updated", "supplier", supplier_id)
    return {"message": "Supplier updated"}

@api_router.delete("/suppliers/{supplier_id}")
async def delete_supplier(supplier_id: str, current_user: Admin = Depends(get_current_user)):
    await db.suppliers.delete_one({"id": supplier_id})
    await log_activity("supplier_deleted", "supplier", supplier_id)
    return {"message": "Supplier deleted"}

# ===== DASHBOARD ROUTES =====

@api_router.get("/dashboard/summary")
async def get_dashboard_summary(current_user: Admin = Depends(get_current_user)):
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_str = today.isoformat()
    
    # Today sales
    today_sales = await db.sales.find({"sale_date": {"$gte": today_str}}).to_list(10000)
    today_sales_total = sum(s['total'] for s in today_sales)
    
    # Today expenses
    today_expenses = await db.expenses.find({"expense_date": {"$gte": today_str}}).to_list(10000)
    today_expenses_total = sum(e['amount'] for e in today_expenses)
    
    # Today profit (simple calculation)
    today_profit = today_sales_total - today_expenses_total
    
    # Month stats
    month_start = today.replace(day=1)
    month_start_str = month_start.isoformat()
    
    month_sales = await db.sales.find({"sale_date": {"$gte": month_start_str}}).to_list(10000)
    month_sales_total = sum(s['total'] for s in month_sales)
    
    month_expenses = await db.expenses.find({"expense_date": {"$gte": month_start_str}}).to_list(10000)
    month_expenses_total = sum(e['amount'] for e in month_expenses)
    
    month_profit = month_sales_total - month_expenses_total
    
    # Low stock products
    low_stock_products = []
    all_products = await db.products.find({}, {"_id": 0}).to_list(1000)
    for p in all_products:
        if p['available_stock_kg'] < p.get('low_stock_threshold', 10):
            low_stock_products.append(p)
    
    # Recent activity
    recent_activity = await db.activity_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(10).to_list(10)
    
    # Best selling products (this month)
    product_sales = {}
    for sale in month_sales:
        pid = sale['product_id']
        if pid not in product_sales:
            product_sales[pid] = {"name": sale['product_name'], "quantity": 0, "revenue": 0}
        product_sales[pid]["quantity"] += sale['quantity_kg']
        product_sales[pid]["revenue"] += sale['total']
    
    best_sellers = sorted(product_sales.values(), key=lambda x: x['revenue'], reverse=True)[:5]
    
    return {
        "today": {
            "sales": today_sales_total,
            "expenses": today_expenses_total,
            "profit": today_profit
        },
        "month": {
            "sales": month_sales_total,
            "expenses": month_expenses_total,
            "profit": month_profit
        },
        "low_stock_products": low_stock_products,
        "recent_activity": recent_activity,
        "best_sellers": best_sellers
    }

# ===== REPORTS ROUTES =====

@api_router.get("/reports/daily")
async def get_daily_report(date: str, current_user: Admin = Depends(get_current_user)):
    target_date = datetime.fromisoformat(date)
    start_str = target_date.isoformat()
    end_str = (target_date + timedelta(days=1)).isoformat()
    
    sales = await db.sales.find({"sale_date": {"$gte": start_str, "$lt": end_str}}).to_list(10000)
    expenses = await db.expenses.find({"expense_date": {"$gte": start_str, "$lt": end_str}}).to_list(10000)
    
    sales_total = sum(s['total'] for s in sales)
    expenses_total = sum(e['amount'] for e in expenses)
    profit = sales_total - expenses_total
    
    return {
        "date": date,
        "sales_count": len(sales),
        "sales_total": sales_total,
        "expenses_count": len(expenses),
        "expenses_total": expenses_total,
        "profit": profit,
        "sales": sales,
        "expenses": expenses
    }

@api_router.get("/reports/monthly")
async def get_monthly_report(month: str, current_user: Admin = Depends(get_current_user)):
    # month format: YYYY-MM
    year, m = month.split("-")
    start_date = datetime(int(year), int(m), 1, tzinfo=timezone.utc)
    if int(m) == 12:
        end_date = datetime(int(year) + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end_date = datetime(int(year), int(m) + 1, 1, tzinfo=timezone.utc)
    
    start_str = start_date.isoformat()
    end_str = end_date.isoformat()
    
    sales = await db.sales.find({"sale_date": {"$gte": start_str, "$lt": end_str}}).to_list(10000)
    expenses = await db.expenses.find({"expense_date": {"$gte": start_str, "$lt": end_str}}).to_list(10000)
    
    sales_total = sum(s['total'] for s in sales)
    expenses_total = sum(e['amount'] for e in expenses)
    profit = sales_total - expenses_total
    
    return {
        "month": month,
        "sales_count": len(sales),
        "sales_total": sales_total,
        "expenses_count": len(expenses),
        "expenses_total": expenses_total,
        "profit": profit
    }

# ===== EXPORTS ROUTES =====

@api_router.post("/exports/pdf")
async def export_pdf(export_type: str = "sales", from_date: str = "", to_date: str = "", current_user: Admin = Depends(get_current_user)):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph(f"<b>KKK RiceTracker - {export_type.upper()} Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    if export_type == "sales":
        sales = await db.sales.find({}).to_list(1000)
        data = [["Date", "Product", "Qty(kg)", "Rate", "Total"]]
        for s in sales:
            data.append([
                s['sale_date'][:10],
                s['product_name'],
                str(s['quantity_kg']),
                str(s['rate_per_kg']),
                str(s['total'])
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(table)
    
    doc.build(elements)
    buffer.seek(0)
    
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={export_type}_report.pdf"}
    )

@api_router.post("/exports/excel")
async def export_excel(export_type: str = "sales", from_date: str = "", to_date: str = "", current_user: Admin = Depends(get_current_user)):
    wb = Workbook()
    ws = wb.active
    ws.title = export_type.upper()
    
    if export_type == "sales":
        ws.append(["Date", "Product", "Qty(kg)", "Rate", "Total", "Payment", "Customer"])
        sales = await db.sales.find({}).to_list(1000)
        for s in sales:
            ws.append([
                s['sale_date'][:10],
                s['product_name'],
                s['quantity_kg'],
                s['rate_per_kg'],
                s['total'],
                s.get('payment_type', ''),
                s.get('customer_name', '')
            ])
    elif export_type == "products":
        ws.append(["Name", "SKU", "Category", "Price/kg", "Cost/kg", "Stock(kg)"])
        products = await db.products.find({}).to_list(1000)
        for p in products:
            ws.append([
                p['name'],
                p['sku'],
                p.get('category', ''),
                p['price_per_kg'],
                p['purchase_cost_per_kg'],
                p['available_stock_kg']
            ])
    
    # Style header
    for cell in ws[1]:
        cell.font = Font(bold=True)
        cell.alignment = Alignment(horizontal='center')
    
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    
    return Response(
        content=buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={export_type}_report.xlsx"}
    )

# ===== ACTIVITY LOG =====

@api_router.get("/activity-logs")
async def get_activity_logs(limit: int = 100, current_user: Admin = Depends(get_current_user)):
    logs = await db.activity_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return {"logs": logs}

# ===== SETTINGS =====

@api_router.get("/settings")
async def get_settings(current_user: Admin = Depends(get_current_user)):
    return {
        "admin": {
            "name": current_user.name,
            "phone": current_user.phone,
            "email": current_user.email
        }
    }

@api_router.put("/settings")
async def update_settings(name: str = "", phone: str = "", email: str = "", current_user: Admin = Depends(get_current_user)):
    update_data = {}
    if name:
        update_data['name'] = name
    if phone:
        update_data['phone'] = phone
    if email:
        update_data['email'] = email
    
    if update_data:
        await db.admins.update_one({"id": current_user.id}, {"$set": update_data})
    
    return {"message": "Settings updated"}

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
