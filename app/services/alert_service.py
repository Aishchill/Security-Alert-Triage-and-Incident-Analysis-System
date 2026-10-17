"""Alert persistence service with atomic transactions and deduplication."""

from typing import List, Optional, Tuple
import logging
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.models.alert import AlertModel
from app.schemas.alert import CanonicalAlert

logger = logging.getLogger("security_triage.alert_service")


class AlertService:
    """Handles alert persistence, querying, and deduplication."""

    @staticmethod
    def get_by_dedup_hash(db: Session, dedup_hash: str) -> Optional[AlertModel]:
        """Find an existing alert by its cryptographic deduplication hash."""
        stmt = select(AlertModel).where(AlertModel.deduplication_hash == dedup_hash)
        return db.execute(stmt).scalars().first()

    @staticmethod
    def get_by_id(db: Session, alert_id: str) -> Optional[AlertModel]:
        """Retrieve an alert by its primary UUID."""
        stmt = select(AlertModel).where(AlertModel.id == alert_id)
        return db.execute(stmt).scalars().first()

    @classmethod
    def save_alert(cls, db: Session, canonical: CanonicalAlert) -> Tuple[AlertModel, bool]:
        """Save a single canonical alert. Returns (AlertModel, is_duplicate).
        
        Idempotent: If deduplication hash exists, returns the existing record.
        """
        existing = cls.get_by_dedup_hash(db, canonical.deduplication_hash)
        if existing:
            return existing, True

        model = AlertModel(
            id=canonical.id,
            source_event_id=canonical.source_event_id,
            source=canonical.source,
            timestamp=canonical.timestamp,
            ingested_at=canonical.ingested_at,
            event_type=canonical.event_type,
            severity=canonical.severity.value,
            confidence=canonical.confidence,
            user_entity=canonical.user_entity,
            host_entity=canonical.host_entity,
            asset_criticality=canonical.asset_criticality.value,
            source_ip=canonical.source_ip,
            destination_ip=canonical.destination_ip,
            destination_port=canonical.destination_port,
            indicators=canonical.indicators,
            title=canonical.title,
            description=canonical.description,
            raw_payload=canonical.raw_payload,
            deduplication_hash=canonical.deduplication_hash,
        )

        try:
            db.add(model)
            db.commit()
            db.refresh(model)
            return model, False
        except IntegrityError:
            # Handle race condition where record was inserted concurrently
            db.rollback()
            existing = cls.get_by_dedup_hash(db, canonical.deduplication_hash)
            if existing:
                return existing, True
            raise

    @classmethod
    def save_alerts_batch(
        cls, db: Session, canonical_list: List[CanonicalAlert]
    ) -> Tuple[List[AlertModel], int]:
        """Save a batch of alerts idempotently.
        
        Returns (newly_persisted_alerts, duplicate_count).
        """
        saved: List[AlertModel] = []
        duplicate_count = 0
        seen_in_batch = set()

        for canonical in canonical_list:
            if canonical.deduplication_hash in seen_in_batch:
                duplicate_count += 1
                continue

            model, is_duplicate = cls.save_alert(db, canonical)
            if is_duplicate:
                duplicate_count += 1
            else:
                saved.append(model)
                seen_in_batch.add(canonical.deduplication_hash)

        return saved, duplicate_count

    @staticmethod
    def list_alerts(
        db: Session,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        user: Optional[str] = None,
        host: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AlertModel], int]:
        """Query alerts with filtering and pagination."""
        stmt = select(AlertModel)
        count_stmt = select(func.count(AlertModel.id))

        if source:
            stmt = stmt.where(AlertModel.source.ilike(f"%{source}%"))
            count_stmt = count_stmt.where(AlertModel.source.ilike(f"%{source}%"))
        if severity:
            stmt = stmt.where(AlertModel.severity == severity.upper())
            count_stmt = count_stmt.where(AlertModel.severity == severity.upper())
        if user:
            stmt = stmt.where(AlertModel.user_entity.ilike(f"%{user}%"))
            count_stmt = count_stmt.where(AlertModel.user_entity.ilike(f"%{user}%"))
        if host:
            stmt = stmt.where(AlertModel.host_entity.ilike(f"%{host}%"))
            count_stmt = count_stmt.where(AlertModel.host_entity.ilike(f"%{host}%"))

        total = db.execute(count_stmt).scalar() or 0
        items = db.execute(
            stmt.order_by(AlertModel.timestamp.desc()).limit(limit).offset(offset)
        ).scalars().all()

        return list(items), total
