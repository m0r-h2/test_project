from fastapi import APIRouter, status, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.schemas.users import User as UserResponse, UserCreate, UserUpdate, UserPassword
from app.models.users import User as UserModel
from app.db_depends import get_async_db
from app.auth import hash_password, verify_password, create_access_token, get_current_user, create_refresh_token

import jwt

from app.config import SECRET_KEY, ALGORITHM


router = APIRouter(prefix="/users",
                   tags=["users"])


@router.get("/", response_model=list[UserResponse], status_code=status.HTTP_200_OK)
async def get_all_active_users(db: AsyncSession = Depends(get_async_db)):
    stmt = await db.scalars(select(UserModel).where(UserModel.is_active == True))
    return stmt


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_async_db)):
    result = await db.scalars(select(UserModel).where(UserModel.email == user.email))
    if result.first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email уже существует")
    if user.password != user.verf_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Пароли не совпадают")

    db_user = UserModel(
        first_name=user.first_name,
        last_name=user.last_name,
        middle_name=user.middle_name,
        email=user.email,
        password_hash=hash_password(user.password),
        role=user.role
    )

    db.add(db_user)
    await db.commit()
    return db_user


@router.post("/refresh-token")
async def refresh_token(refresh_token: str, db: AsyncSession = Depends(get_async_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    result = await db.scalars(select(UserModel).where(UserModel.email == email, UserModel.is_active == True))
    user = result.first()
    if user is None:
        raise credentials_exception
    access_token = create_access_token(data={"sub": user.email, "role": user.role, "id": user.id})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_async_db)):
    result = await db.scalars(
        select(UserModel).where(UserModel.email == form_data.username, UserModel.is_active == True))
    user = result.first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Некорректный Email или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email, "role": user.role, "id": user.id})
    refresh_token = create_refresh_token(data={"sub": user.email, "role": user.role, "id": user.id})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.put("/me")
async def update_account(
        data: UserUpdate,
        current_user: UserModel = Depends(get_current_user),
        db: AsyncSession = Depends(get_async_db)
):
    update_data = data.model_dump(exclude_unset=True)

    update_data["password_hash"] = hash_password(data.password_hash)

    await db.execute(
        update(UserModel)
        .where(UserModel.id == current_user.id)
        .values(**update_data)
    )
    await db.commit()

    await db.refresh(current_user)

    return {"message": "Вы успешно обновили свой аккаунт"}


@router.delete("/", status_code=status.HTTP_200_OK)
async def delete_me_account(password: UserPassword,
                            current_user: UserModel = Depends(get_current_user),
                            db: AsyncSession = Depends(get_async_db)):
    if not verify_password(password.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password")

    await db.execute(
        update(UserModel)
        .where(UserModel.id == current_user.id)
        .values(is_active=False)
    )
    await db.commit()
    return {"message": "Аккаунт удален"}
