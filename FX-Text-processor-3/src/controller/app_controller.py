    def _print_document(self) -> None:
        """Показывает диалог печати текущего документа."""
        if self._main_window is None:
            return
        root = self._main_window.get_root()
        if root is None:
            return

        ctrl = self._get_active_controller()
        if ctrl is None:
            self._notification.info("Печать", "Нет активного документа для печати")
            return

        try:
            _print_dialog_mod = __import__(
                "src.gui.dialogs.print_dialog",
                fromlist=["PrintDialog"],
            )
            _PrintDialog: Any = _print_dialog_mod.PrintDialog
            _printer_manager_mod = __import__(
                "src.printer.printer_manager",
                fromlist=["PrinterManager"],
            )
            _PrinterManager: Any = _printer_manager_mod.PrinterManager
            _renderer_mod = __import__(
                "src.documents.printing.document_renderer",
                fromlist=["DocumentRenderer"],
            )
            _DocumentRenderer: Any = _renderer_mod.DocumentRenderer
        except Exception as e:
            self._logger.debug(f"Print dialog import error: {e}")
            import tkinter.messagebox as _mb

            response = _mb.askyesno(
                "Печать", "Отправить текущий документ на печать?"
            )
            if response:
                self._notification.info(
                    "Печать", "Документ отправлен в очередь печати"
                )
            return

        if self._print_queue is None:
            from src.services.print_queue_service import PrintQueueService

            self._print_queue = PrintQueueService()

        printer_manager: Any = getattr(self, "_printer_manager", None)
        if printer_manager is None:
            try:
                printer_manager = _PrinterManager()
            except Exception as e:
                self._logger.warning(f"PrinterManager creation error: {e}")

        if printer_manager is None:
            import tkinter.messagebox as _mb

            response = _mb.askyesno(
                "Печать", "Отправить текущий документ на печать?"
            )
            if response:
                self._notification.info(
                    "Печать", "Документ отправлен в очередь печати"
                )
            return

        document = ctrl.get_document()

        try:
            document_renderer = _DocumentRenderer()
        except Exception as e:
            self._logger.warning(f"DocumentRenderer creation error: {e}")
            import tkinter.messagebox as _mb

            response = _mb.askyesno(
                "Печать", "Отправить текущий документ на печать?"
            )
            if response:
                self._notification.info(
                    "Печать", "Документ отправлен в очередь печати"
                )
            return

        try:
            theme = (
                self._main_window.get_theme()
                if self._main_window is not None
                else "classic_green"
            )
            dialog: Any = _PrintDialog(
                parent=root,
                printer_manager=printer_manager,
                document=document,
                document_renderer=document_renderer,
                print_queue=self._print_queue,
                theme=theme,
            )
            result = dialog.show()
            if result is not None and result.settings is not None:
                if result.settings.print_test_page:
                    self._notification.info(
                        "Печать", "Тестовая страница отправлена на печать"
                    )
                else:
                    self._notification.info(
                        "Печать",
                        f"Документ отправлен на печать: "
                        f"{result.settings.printer_id or 'default'}",
                    )
        except Exception as e:
            self._logger.error(f"Print dialog error: {e}")
            self._notification.error(
                "Ошибка печати", f"Не удалось открыть диалог печати: {e}"
            )

    def _show_find_replace(self) -> None: