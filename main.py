from datetime import datetime, timedelta, timezone
import os
import re
import secrets

from dotenv import load_dotenv
import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship


load_dotenv()

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine("sqlite:///./social.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    posts = relationship("Post", back_populates="author")
    followers = relationship(
        "Follow", foreign_keys="Follow.following_id", back_populates="following"
    )
    following = relationship(
        "Follow", foreign_keys="Follow.follower_id", back_populates="follower"
    )


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text)
    slug = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    author = relationship("User", back_populates="posts")


class Follow(Base):
    __tablename__ = "follows"
    id = Column(Integer, primary_key=True, index=True)
    follower_id = Column(Integer, ForeignKey("users.id"))
    following_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    follower = relationship("User", foreign_keys=[follower_id])
    following = relationship("User", foreign_keys=[following_id])


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    post_id = Column(Integer, ForeignKey("posts.id"))
    post_slug = Column(String)
    author_email = Column(String)
    post_preview = Column(String)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class PostCreate(BaseModel):
    content: str


def create_slug(content: str) -> str:
    words = re.findall(r"\w+", content.lower())[:5]
    slug_words = "-".join(words)
    random_suffix = secrets.token_hex(4)
    return f"{slug_words}-{random_suffix}"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.get("/")
async def read_root():
    return FileResponse("static/index.html")


@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer", "email": user.email}


@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer", "email": user.email}


@app.post("/posts")
def create_post(
    post: PostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not post.content.strip():
        raise HTTPException(status_code=400, detail="Post content cannot be empty")

    slug = create_slug(post.content)
    while db.query(Post).filter(Post.slug == slug).first():
        slug = create_slug(post.content)

    db_post = Post(content=post.content, slug=slug, user_id=current_user.id)
    db.add(db_post)
    db.commit()
    db.refresh(db_post)

    preview = post.content[:50] + "..." if len(post.content) > 50 else post.content
    followers = db.query(Follow).filter(Follow.following_id == current_user.id).all()
    for follow in followers:
        notification = Notification(
            user_id=follow.follower_id,
            post_id=db_post.id,
            post_slug=slug,
            author_email=current_user.email,
            post_preview=preview,
        )
        db.add(notification)
    db.commit()

    return {
        "id": db_post.id,
        "content": db_post.content,
        "slug": db_post.slug,
        "created_at": db_post.created_at,
    }


@app.get("/posts")
def get_posts(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    posts = db.query(Post).join(User).order_by(Post.created_at.desc()).limit(20).all()
    return [
        {
            "id": p.id,
            "content": p.content,
            "slug": p.slug,
            "author": p.author.email,
            "created_at": p.created_at,
        }
        for p in posts
    ]


@app.get("/post/{slug}")
def get_post_by_slug(
    slug: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(Post).filter(Post.slug == slug).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return {
        "id": post.id,
        "content": post.content,
        "slug": post.slug,
        "author": post.author.email,
        "created_at": post.created_at,
    }


@app.get("/users")
def get_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    users = db.query(User).filter(User.id != current_user.id).all()
    following_ids = [
        f.following_id
        for f in db.query(Follow).filter(Follow.follower_id == current_user.id).all()
    ]
    return [
        {"id": u.id, "email": u.email, "is_following": u.id in following_ids}
        for u in users
    ]


@app.post("/follow/{user_id}")
def follow_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")

    existing_follow = (
        db.query(Follow)
        .filter(Follow.follower_id == current_user.id, Follow.following_id == user_id)
        .first()
    )

    if existing_follow:
        raise HTTPException(status_code=400, detail="Already following this user")

    follow = Follow(follower_id=current_user.id, following_id=user_id)
    db.add(follow)
    db.commit()
    return {"message": "User followed successfully"}


@app.delete("/unfollow/{user_id}")
def unfollow_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    follow = (
        db.query(Follow)
        .filter(Follow.follower_id == current_user.id, Follow.following_id == user_id)
        .first()
    )

    if not follow:
        raise HTTPException(status_code=400, detail="Not following this user")

    db.delete(follow)
    db.commit()
    return {"message": "User unfollowed successfully"}


@app.get("/notifications/count")
def get_notification_count(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    count = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id, Notification.is_read == False)
        .count()
    )
    return {"count": count}


@app.get("/notifications")
def get_notifications(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    notifications = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc())
        .limit(10)
        .all()
    )

    for notification in notifications:
        notification.is_read = True
    db.commit()

    return [
        {
            "id": n.id,
            "author_email": n.author_email,
            "post_preview": n.post_preview,
            "post_slug": n.post_slug,
            "created_at": n.created_at,
        }
        for n in notifications
    ]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
