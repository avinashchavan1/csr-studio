package com.example.csrgen.persistence;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CsrShareRepository extends JpaRepository<CsrShare, String> {

    List<CsrShare> findByOrderByCreatedAtAsc(Pageable pageable);
}
