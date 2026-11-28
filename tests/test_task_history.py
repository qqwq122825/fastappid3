import json
import os
import tempfile
import unittest
from unittest import mock

import web


class TaskHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.data = os.path.join(self.root, 'data')
        self.history = os.path.join(self.data, 'task-history')
        os.makedirs(self.history)
        self.patches = [
            mock.patch.object(web, 'HERE', self.root),
            mock.patch.object(web, 'TASK_HISTORY_DIR', self.history),
            mock.patch.dict(web.STATE, {
                'run_out': '', 'started_at': 0, 'accounts': '', 'threads': 1,
                'processes': 1, 'total': 0,
            }),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.tmp.cleanup()

    def write_rows(self, task_id, suffix='', count=3):
        path = os.path.join(self.data, f'{task_id}{suffix}.jsonl')
        with open(path, 'w', encoding='utf-8') as handle:
            for index in range(count):
                handle.write(json.dumps({
                    'email': f'user{index}@example.com',
                    'status': 'timeout' if index == 0 else 'locked',
                }) + '\n')
        return path

    def test_history_lists_metadata_without_exposing_paths(self):
        task_id = 'run-1795840000'
        self.write_rows(task_id, '-p0', 2)
        self.write_rows(task_id, '-p1', 2)
        web._write_task_history_record({
            'id': task_id, 'started_at': 1795840000, 'updated_at': 1795840001,
            'account_name': 'accounts.txt', 'accounts': '/secret/accounts.txt',
            'total': 4, 'done': 4, 'processes': 2, 'threads': 2,
            'total_threads': 4, 'status': 'complete', 'elapsed': 1.2,
            'by_status': {'locked': 3, 'timeout': 1}, 'version': 'test',
        })
        result = web.task_history(page=1, limit=20)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['rows'][0]['file_count'], 2)
        self.assertEqual(result['rows'][0]['done'], 4)
        self.assertNotIn('accounts', result['rows'][0])
        self.assertNotIn('/secret/', json.dumps(result))

    def test_legacy_results_are_discovered_and_search_is_paginated(self):
        self.write_rows('run-1795840001', count=1)
        self.write_rows('run-1795840002', count=1)
        result = web.task_history(page=1, limit=1, query='run-179584000')
        self.assertEqual(result['total'], 2)
        self.assertEqual(result['pages'], 2)
        self.assertTrue(result['has_next'])
        self.assertEqual(result['rows'][0]['status'], 'archived')

    def test_historical_results_are_scoped_by_opaque_task_id(self):
        first = 'run-1795840010'
        second = 'run-1795840011'
        self.write_rows(first, count=3)
        self.write_rows(second, count=7)
        handler = object.__new__(web.Handler)
        result = handler._results('all', limit=100, page=1, task_id=first)
        self.assertEqual(result['total'], 3)
        self.assertEqual(result['task_id'], first)
        invalid = handler._results('all', task_id='../run-1795840011')
        self.assertIn('error', invalid)
        self.assertEqual(invalid['rows'], [])

    def test_delete_removes_only_selected_idle_task(self):
        selected = 'run-1795840020'
        other = 'run-1795840021'
        selected_path = self.write_rows(selected, count=1)
        other_path = self.write_rows(other, count=1)
        web._write_task_history_record({'id': selected, 'started_at': 1})
        with mock.patch.object(web, 'is_running', return_value=False):
            result = web.delete_task_history(selected)
        self.assertTrue(result['ok'])
        self.assertFalse(os.path.exists(selected_path))
        self.assertTrue(os.path.exists(other_path))
        self.assertFalse(os.path.exists(web._task_history_path(selected)))

    def test_bulk_delete_removes_selected_tasks_and_preserves_other(self):
        selected = ['run-1795840030', 'run-1795840031']
        other = 'run-1795840032'
        selected_paths = [self.write_rows(task_id, count=1) for task_id in selected]
        other_path = self.write_rows(other, count=1)
        for task_id in selected + [other]:
            web._write_task_history_record({'id': task_id, 'started_at': 1})
        with mock.patch.object(web, 'is_running', return_value=False):
            result = web.delete_task_histories(selected)
        self.assertTrue(result['ok'])
        self.assertEqual(result['deleted'], selected)
        self.assertTrue(all(not os.path.exists(path) for path in selected_paths))
        self.assertTrue(os.path.exists(other_path))

    def test_bulk_delete_rejects_empty_or_oversized_selection(self):
        self.assertIn('error', web.delete_task_histories([]))
        oversized = [f'run-{1795841000 + index}' for index in range(201)]
        self.assertIn('error', web.delete_task_histories(oversized))

    def test_page_contains_history_controls(self):
        self.assertIn('id="taskHistoryModal"', web.PAGE)
        self.assertIn('id="taskHistory"', web.PAGE)
        self.assertIn('id="currentResults"', web.PAGE)
        self.assertIn('task_id=', web.PAGE)
        self.assertIn('id="selectAllTaskHistory"', web.PAGE)
        self.assertIn('id="deleteSelectedTasks"', web.PAGE)
        self.assertIn('data-select-task=', web.PAGE)


if __name__ == '__main__':
    unittest.main()
