package com.example.csrgen.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CsrHistoryRepository extends JpaRepository<CsrHistory, String> {

    List<CsrHistory> findTop40ByOrderByCreatedAtDesc();
}
