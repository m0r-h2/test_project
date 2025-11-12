from fastapi import APIRouter, status, Depends, HTTPException

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.schemas.users import User as UserResponse, UserPassword, UserUpdateAdmin
from app.models.users import User as UserModel
from app.db_depends import get_async_db
from app.auth import verify_password, get_current_role_admin

router = APIRouter(prefix="/admins",
                   tags=["admins"])


@router.get("/", response_model=list[UserResponse], status_code=status.HTTP_200_OK)
async def get_all_active_users(current_admin: UserModel = Depends(get_current_role_admin),
                               db: AsyncSession = Depends(get_async_db)):
    stmt = await db.scalars(select(UserModel).where(UserModel.is_active == True))
    return stmt.all()


@router.get("/deleted_all_user", response_model=list[UserResponse], status_code=status.HTTP_200_OK)
async def get_all_deleted_users(current_admin: UserModel = Depends(get_current_role_admin),
                                db: AsyncSession = Depends(get_async_db)):
    stmt = await db.scalars(select(UserModel).where(UserModel.is_active == False))
    return stmt.all()


@router.put("/{id_account}")
async def update_user_account_id(
        id_account: int,
        data: UserUpdateAdmin,
        current_user: UserModel = Depends(get_current_role_admin),
        db: AsyncSession = Depends(get_async_db)
):
    update_data = data.model_dump(exclude_unset=True)

    await db.execute(
        update(UserModel)
        .where(UserModel.id == id_account)
        .values(**update_data)
    )
    await db.commit()

    return {"message": "Изменения сохранены"}


@router.delete("/{account_id}", response_model=dict, status_code=status.HTTP_200_OK)
async def delete_account_id(account_id: int,
                            password: UserPassword,
                            current_user: UserModel = Depends(get_current_role_admin),
                            db: AsyncSession = Depends(get_async_db)):
    if not verify_password(password.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Неверный пароль")

    stmt = await db.scalars(select(UserModel).where(UserModel.id == account_id,
                                                    UserModel.is_active == True))

    if not stmt.all():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Аккаунт либо удален либо не существует")

    await db.execute(
        update(UserModel)
        .where(UserModel.id == account_id)
        .values(is_active=False)
    )
    await db.commit()
    return {"message": "Аккаунт удален"}
