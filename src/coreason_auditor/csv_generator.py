# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import csv
from typing import List

from coreason_auditor.models import ConfigChange
from coreason_auditor.utils.logger import logger


class CSVGenerator:
    """Generates CSV exports for audit data."""

    def generate_config_change_log(self, config_changes: List[ConfigChange], output_path: str) -> None:
        """Exports the configuration change log to a CSV file.

        Args:
            config_changes: List of ConfigChange objects containing audit trail data.
            output_path: Destination file path for the CSV export.

        Raises:
            IOError: If writing to the file fails.
        """
        logger.info(f"Generating Config Change CSV at {output_path}...")

        headers = [
            "Change ID",
            "Timestamp",
            "User ID",
            "Field Changed",
            "Old Value",
            "New Value",
            "Reason",
            "Status",
        ]

        try:
            with open(output_path, mode="w", newline="", encoding="utf-8") as csv_file:
                writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
                writer.writerow(headers)

                for change in config_changes:
                    writer.writerow(
                        [
                            change.change_id,
                            change.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                            change.user_id,
                            change.field_changed,
                            change.old_value,
                            change.new_value,
                            change.reason,
                            change.status,
                        ]
                    )
            logger.info("CSV generation successful.")
        except IOError as e:
            logger.error(f"Failed to write CSV file: {e}")
            raise
